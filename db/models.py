"""
db/models.py
=============
SQLAlchemy ORM models — defines the database schema for the application.

This module maps Python classes to database tables. Each class represents a table,
and each class attribute represents a column. SQLAlchemy's ORM layer handles all
SQL generation, so the rest of the application can work with Python objects rather
than raw SQL strings.

Database tables:
  - users          — registered users (owner of projects)
  - projects       — named groupings of scans (e.g., "My Web App")
  - configs        — saved scan configurations (tools + options) per project
  - scans          — individual scan runs with status tracking
  - findings       — individual vulnerability findings linked to a scan
  - ai_explanations — LLM-generated explanations for findings
  - fix_suggestions — LLM-generated fix recommendations
  - risk_scores    — numeric risk scores assigned to findings
  - feedback       — analyst ratings/comments on findings (false positive tracking)

Relationships:
  User → (has many) → Projects
  Project → (has many) → Configs, Scans
  Scan → (has many) → Findings
  Finding → (has many) → AIExplanations, FixSuggestions, RiskScores, Feedback

All timestamp fields use the database server's current time (server_default=func.now())
rather than Python's datetime.now() to avoid clock skew issues in distributed setups.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from db.base import Base


class User(Base):
    """
    A registered user who owns one or more projects.

    Currently used to associate projects with an owner. Authentication is not
    implemented in this version — the user record is a foundation for future
    multi-user support.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")


class Project(Base):
    """
    A named project that groups related scan configurations and scan results.

    For example, a project called "DVWA Lab" might contain multiple scan configs
    (SAST only, DAST full web, quick nuclei) and accumulate all scan history.

    The unique constraint on (owner_id, name) prevents two projects with the same
    name under the same user.
    """
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    owner = relationship("User", back_populates="projects")
    configs = relationship("Config", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("owner_id", "name", name="uq_projects_owner_name"),
    )


class Config(Base):
    """
    A saved scan configuration belonging to a project.

    Stores the list of tools to run and any tool-specific options, so the same
    scan can be re-run without repeating all the CLI flags. For example:
      - name: "quick SAST"
        tools: ["semgrep"]
        options: {"semgrep": {"config": "p/owasp-top-ten", "timeout_seconds": 120}}

    The unique constraint on (project_id, name) prevents duplicate config names
    within a single project.
    """
    __tablename__ = "configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    tools = Column(JSON, nullable=False, default=list)    # e.g., ["semgrep", "hexstrike"]
    options = Column(JSON, nullable=False, default=dict)  # tool-specific option dicts
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    project = relationship("Project", back_populates="configs")

    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_configs_project_name"),
    )


class Scan(Base):
    """
    A single scan run — the top-level record for a set of findings.

    Tracks the lifecycle of a scan from "running" through to "completed" or
    "completed_with_errors". Each scan is assigned a UUID-based scan_id (the
    public identifier used in API responses) and an auto-increment integer id
    (the internal foreign key used by Finding records).

    status values: "running" | "completed" | "completed_with_errors"
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(128), nullable=False, unique=True, index=True)  # public UUID
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)

    target_path = Column(Text, nullable=False)     # filesystem path or URL that was scanned
    tools = Column(JSON, nullable=False, default=list)
    options = Column(JSON, nullable=False, default=dict)

    status = Column(String(32), nullable=False, default="running", index=True)
    error = Column(Text, nullable=True)  # error message if scan failed

    started_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)  # null until scan completes
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    """
    A single vulnerability finding from a scan.

    Stores all information about one security issue: what it is, how severe it is,
    where it was found, and the raw metadata from the tool that detected it. SAST
    findings include file_path and line; DAST findings use the JSON location field
    to store url, endpoint, and parameter.

    The composite index on (scan_id, source, severity) speeds up common queries
    such as "show me all HIGH findings from semgrep in this scan".

    Note: The 'meta' attribute maps to a database column named 'metadata'.
    SQLAlchemy reserves 'metadata' as an attribute name on mapped classes, so
    'meta' is used as the Python attribute name to avoid conflicts.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)

    external_id = Column(String(512), nullable=False, index=True)  # tool-generated finding ID
    source = Column(String(64), nullable=False, index=True)         # e.g., "semgrep", "hexstrike"
    severity = Column(String(16), nullable=False, index=True)       # CRITICAL/HIGH/MEDIUM/LOW/INFO
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)

    # SAST location fields (null for DAST findings)
    file_path = Column(Text, nullable=True)
    line = Column(Integer, nullable=True)
    column = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    end_column = Column(Integer, nullable=True)

    # Security classification
    cwe_id = Column(String(32), nullable=True, index=True)        # e.g., "CWE-89"
    owasp_category = Column(String(64), nullable=True)            # e.g., "A03:2021 - Injection"
    confidence = Column(Float, nullable=True)                     # 0.0 – 1.0

    location = Column(JSON, nullable=False, default=dict)         # raw location object
    meta = Column("metadata", JSON, nullable=False, default=dict) # raw tool output

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    scan = relationship("Scan", back_populates="findings")
    ai_explanations = relationship(
        "AIExplanation", back_populates="finding", cascade="all, delete-orphan"
    )
    fix_suggestions = relationship(
        "FixSuggestion", back_populates="finding", cascade="all, delete-orphan"
    )
    risk_scores = relationship(
        "RiskScore", back_populates="finding", cascade="all, delete-orphan"
    )
    feedback = relationship(
        "Feedback", back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Composite index speeds up severity-filtered queries within a scan.
        Index("ix_findings_scan_source_sev", "scan_id", "source", "severity"),
    )


class AIExplanation(Base):
    """
    An LLM-generated explanation for a vulnerability finding.

    Stores the plain-English explanation produced by the DeepSeek model, including
    what the vulnerability means and how an attacker might exploit it. The 'model'
    column records which LLM was used so explanations from different model versions
    can be compared or regenerated.
    """
    __tablename__ = "ai_explanations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)

    model = Column(String(128), nullable=True)       # e.g., "deepseek-r1:8b"
    explanation = Column(Text, nullable=False)
    meta = Column("metadata", JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    finding = relationship("Finding", back_populates="ai_explanations")


class FixSuggestion(Base):
    """
    An LLM-generated remediation suggestion for a vulnerability finding.

    Stores the concrete fix or mitigation recommended by the LLM. The optional
    'patch' column is reserved for storing diff-style patches in future.
    """
    __tablename__ = "fix_suggestions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)

    model = Column(String(128), nullable=True)
    suggestion = Column(Text, nullable=False)
    patch = Column(Text, nullable=True)  # diff/patch format (reserved for future use)
    meta = Column("metadata", JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    finding = relationship("Finding", back_populates="fix_suggestions")


class RiskScore(Base):
    """
    A numeric risk score calculated for a finding.

    Risk scores allow findings to be prioritised beyond simple severity levels.
    For example, a HIGH-severity finding in a file that is never called from
    user-facing code might have a lower risk score than a MEDIUM finding in a
    public API endpoint.

    The 'rationale' column stores the reasoning behind the score for auditability.
    """
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)

    score = Column(Float, nullable=False)           # numeric risk score
    rationale = Column(Text, nullable=True)         # explanation of the score
    meta = Column("metadata", JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    finding = relationship("Finding", back_populates="risk_scores")


class Feedback(Base):
    """
    Analyst feedback on a finding — used for false positive tracking.

    Security analysts reviewing findings can mark them as false positives, rate
    the accuracy of the detection, or add comments. This data can be used to
    improve future scanning rules or LLM explanations.

    rating: 1–5 scale (1 = false positive, 5 = critical real finding)
    """
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    rating = Column(Integer, nullable=True)         # 1–5 accuracy rating
    comment = Column(Text, nullable=True)
    meta = Column("metadata", JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    finding = relationship("Finding", back_populates="feedback")
