# Comprehensive Dissertation Analysis Report
## Security AI Assistant — Unified SAST + DAST Security Scanning Pipeline

---

## A. Requirements Analysis

### A.1 Functional Requirements

The following functional requirements are evidenced by implemented features, documentation, schemas, and CLI argument definitions across the codebase.

#### FR-01 — SAST Scanning
The system shall perform static application security testing on a local source-code directory using the Semgrep engine. This is evidenced by `SemgrepAdapter` (`adapters/semgrep_adapter.py`) and the `--scan SAST --sast-path` CLI flags in `security_assistant.py`.

#### FR-02 — DAST Scanning
The system shall perform dynamic application security testing against a running web application target. This is evidenced by `HexStrikeAdapter` (`adapters/hexstrike_adapter.py`) and the `--scan DAST --dast-target` CLI flags.

#### FR-03 — Combined SAST + DAST
The system shall support running both SAST and DAST scans in a single invocation. This is evidenced by `--scan SAST,DAST` in `security_assistant.py:run_cli()` and the `execute_scan()` method in `orchestrator/workflow_manager.py`, which iterates over multiple adapter types.

#### FR-04 — Multi-Tool DAST Support
The system shall support at least 30 distinct DAST tools (e.g., Nuclei, SQLMap, FFUF, Nikto, Dalfox, HTTPX, WAFw00f, Gobuster, Dirsearch). This is evidenced by the tool endpoint map in `hexstrike_adapter.py` and the `--dast-tool` flag accepting tool names or the aliases `all-web`, `all-recon`, etc.

#### FR-05 — Standardised Finding Schema
The system shall normalise findings from all tools into a common vulnerability representation. This is evidenced by `schemas/security.py` defining `Vulnerability`, `VulnerabilityLocation`, and the `normalize_results()` method on every adapter.

#### FR-06 — Finding Deduplication
The system shall deduplicate findings across tools within a single scan. This is evidenced by `orchestrator/result_merger.py`, which keys on `(title, source, file_path, line)`.

#### FR-07 — Persistent Storage
The system shall persist scan metadata and all findings to a database for later retrieval. This is evidenced by `db/models.py` (9 tables), `db/crud.py`, and the `save_to_db()` call in `workflow_manager.py`.

#### FR-08 — REST API Interface
The system shall expose a REST API allowing scans to be triggered programmatically. This is evidenced by `backend/app/main.py` (FastAPI), `backend/app/api/v1/endpoints/security.py` (`POST /api/v1/security/scan`), and health check at `GET /health`.

#### FR-09 — CLI Interface
The system shall expose a command-line interface for direct use. This is evidenced by `security_assistant.py` using `argparse` with over 40 flags.

#### FR-10 — LLM-Powered Explanations
The system shall optionally generate plain-English explanations and remediation suggestions for findings using a locally-hosted LLM. This is evidenced by `ai_engine/__init__.py` (Ollama integration) and the `--llm-explain` flag.

#### FR-11 — Saved Scan Configurations
The system shall allow reusable named scan profiles to be stored and retrieved. This is evidenced by the `Config` ORM model (`db/models.py`), `create_config()` / `get_config_by_id()` in `db/crud.py`, and the `config_id` field on `ScanRequest`.

#### FR-12 — Project-Based Scan Organisation
The system shall associate scans with user-defined projects. This is evidenced by the `Project` and `User` models in `db/models.py` and foreign-key relationships throughout.

#### FR-13 — User Feedback on Findings
The system shall allow users to rate and comment on individual findings. This is evidenced by the `Feedback` model (`db/models.py:Feedback`) with `rating` (1–5) and `comment` fields.

#### FR-14 — Severity Classification
The system shall classify findings by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO. This is evidenced by the `SeverityLevel` enum in `schemas/security.py` and the severity mapping logic in both adapters.

#### FR-15 — CWE and OWASP Categorisation
The system shall associate findings with relevant CWE identifiers and OWASP Top 10 categories where possible. This is evidenced by `cwe_id` and `owasp_category` fields in `schemas/security.py:Vulnerability` and `db/models.py:Finding`.

#### FR-16 — Custom Semgrep Rules
The system shall support custom, project-specific static analysis rules. This is evidenced by `semgrep-rules/security-best-practices.yml`, which defines three custom rules targeting JavaScript JWT and localStorage misuse.

#### FR-17 — Automatic Tool Installation
The system shall auto-detect missing DAST tools and attempt to install them. This is evidenced by `scripts/install_tools.py` supporting `go install`, `brew`, `apt-get`, and `pip` installation methods.

#### FR-18 — Automatic HexStrike Server Management
The system shall auto-start the HexStrike server if it is not already running. This is evidenced by `_ensure_hexstrike_running()` in `security_assistant.py`.

#### FR-19 — Export Formats
The system shall support exporting results in at least JSON format. This is evidenced by `normalizer/format_converter.py:to_json()`. SARIF, CSV, and HTML are documented as planned but not implemented.

#### FR-20 — Runtime Security Header Checks
The CLI shall check the scanned target's HTTP security headers (CSP, HSTS, X-Frame-Options, etc.). This is evidenced by `_runtime_security_checks()` in `security_assistant.py`.

---

### A.2 Non-Functional Requirements

#### NFR-01 — Asynchronous I/O
The system shall not block the event loop on I/O operations. This is evidenced by `asyncio.create_subprocess_exec()` in `SemgrepAdapter`, `asyncio.to_thread()` in `HexStrikeAdapter`, and async SQLAlchemy sessions throughout.

#### NFR-02 — Separation of Concerns
Each layer (interface, orchestration, adapter, persistence) shall be independently maintainable. This is evidenced by the five-layer architecture described in Section B.

#### NFR-03 — Extensibility
Adding a new security tool shall require only implementing two methods: `scan()` and `normalize_results()`. This is evidenced by `adapter_base.py` defining a formal ABC contract.

#### NFR-04 — Input Validation
All inputs at API boundaries shall be validated via Pydantic models before processing. This is evidenced by `ScanRequest` in `schemas/security.py` and FastAPI's automatic validation pipeline.

#### NFR-05 — Database Portability
The database backend shall be switchable from SQLite to PostgreSQL without code changes. This is evidenced by `db/database.py:_normalize_async_sqlite_url()` and the use of SQLAlchemy ORM throughout (no raw SQL).

#### NFR-06 — Process Timeout
Semgrep subprocess calls shall not run indefinitely. A 300-second timeout with explicit process kill is enforced in `SemgrepAdapter.scan()`.

#### NFR-07 — Graceful Degradation
A failure in one scanning tool shall not abort the entire pipeline. This is evidenced by try/except blocks in `workflow_manager.py:execute_scan()`, which collects errors and continues.

#### NFR-08 — Structured Logging
All components shall emit structured log entries. This is evidenced by the use of `loguru` throughout (`from loguru import logger`), configured at startup in `backend/app/main.py`.

#### NFR-09 — Security of the System Itself
The system shall implement defences against common web vulnerabilities in its own API. This is evidenced by `backend/app/core/security.py` (path traversal prevention), CORS configuration in `main.py`, and Pydantic input sanitisation.

#### NFR-10 — Platform Support
The system shall run on macOS and Linux. This is evidenced by platform detection in `scripts/install_tools.py` branching on `sys.platform` for macOS (`brew`) vs Linux (`apt-get`).

---

### A.3 Implicit Requirements

The following requirements are inferred from implementation decisions rather than explicit documentation:

- **Confidence scoring**: Every normalised finding carries a `confidence` float (0.0–1.0), implying a requirement to distinguish reliable findings from heuristic detections.
- **Scan status tracking**: The `Scan.status` field (`running` / `completed` / `completed_with_errors`) implies a requirement to track scan lifecycle for API consumers.
- **Risk scoring extensibility**: The `RiskScore` model in `db/models.py` implies a planned requirement for automated risk quantification beyond severity labels.
- **Multi-user tenancy**: The `User` and `Project` models with ownership relationships imply a future requirement for role-based access, even though authentication is not yet implemented.

---

### A.4 Requirement Origins

Based on file evidence:

- **OWASP Top 10 / CWE references**: Explicit references in `README.md` and field names (`owasp_category`, `cwe_id`) indicate requirements drawn from established security standards literature.
- **Tool selection**: The 30+ DAST tools listed correspond to the contemporary professional penetration-testing toolchain, suggesting requirements derived from industry practice.
- **Safety controls** (`--allow-any-path`, `--dast-authorized`, `DAST_ALLOWLIST`): The explicit opt-in design for potentially harmful operations implies an ethical/legal requirement, likely informed by responsible-disclosure and penetration-testing authorisation norms.

**Notable absence**: No formal requirements document (e.g., SRS, user story backlog, issue tracker export) is present in the repository. Requirements have been reconstructed entirely from implemented features and documentation.

---

---

## B. Methodology and Design of the Artefact

### B.1 Software Development Methodology

No explicit process documentation (sprint plans, kanban board exports, or issue tracker files) is present in the repository. However, the following evidence suggests an **iterative, feature-driven development approach**:

- The `docs/DISSERTATION_ANALYSIS.md` references a numbered **Phase Roadmap** (Phase 1 through Phase 10+), with distinct capabilities assigned per phase (e.g., Phase 5: GET retrieval endpoints; Phase 6: authentication; Phase 9: Vue.js dashboard). This indicates planned incremental delivery.
- The git commit history shows five commits with messages indicating progressive stages: initial commit, refactoring for student profile, cleanup, structural updates, and README addition. This is consistent with iterative refinement.
- The `Implementation Completeness` section of `DISSERTATION_ANALYSIS.md` assesses individual components by percentage, consistent with iterative sprint-style tracking of partial completion.
- The `alembic/versions/0001_phase1_tables.py` filename explicitly labels the migration as "phase1", corroborating the phased approach.

The methodology most closely resembles **iterative incremental development** with phase-gated scope rather than a formal Agile (Scrum/Kanban) framework, as no sprint ceremonies or backlog tooling artefacts are present.

---

### B.2 System Architecture

The system employs a **five-layer, vertically-integrated architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│  INTERFACE LAYER                                            │
│  ┌──────────────────────┐  ┌──────────────────────────────┐ │
│  │  CLI                 │  │  FastAPI REST API            │ │
│  │  security_assistant  │  │  backend/app/main.py         │ │
│  │  .py (argparse)      │  │  POST /api/v1/security/scan  │ │
│  └──────────┬───────────┘  └────────────┬─────────────────┘ │
└─────────────┼──────────────────────────┼────────────────────┘
              │                          │
┌─────────────▼──────────────────────────▼────────────────────┐
│  ORCHESTRATION LAYER                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  WorkflowManager (orchestrator/workflow_manager.py)  │   │
│  │  - Input validation (path + DAST target)             │   │
│  │  - Adapter dispatch                                  │   │
│  │  - Result merging                                    │   │
│  │  - DB persistence                                    │   │
│  └──────────────────────────┬───────────────────────────┘   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  ResultMerger (orchestrator/result_merger.py)         │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  ADAPTER LAYER                                              │
│  ┌───────────────────────┐  ┌──────────────────────────┐   │
│  │  SemgrepAdapter       │  │  HexStrikeAdapter        │   │
│  │  adapters/semgrep_    │  │  adapters/hexstrike_     │   │
│  │  adapter.py           │  │  adapter.py              │   │
│  └───────────┬───────────┘  └────────────┬─────────────┘   │
│              │  <<ABC>>                  │                  │
│  ┌───────────▼───────────────────────────▼─────────────┐   │
│  │  SecurityToolAdapter (adapters/adapter_base.py)      │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  INTEGRATION LAYER (External Tools)                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────┐  │
│  │  Semgrep CLI     │  │  HexStrike REST  │  │  Ollama  │  │
│  │  (subprocess)    │  │  API (port 4444) │  │  (LLM)   │  │
│  └──────────────────┘  └──────────────────┘  └──────────┘  │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  PERSISTENCE LAYER                                          │
│  ┌────────────────┐  ┌──────────────────┐  ┌────────────┐  │
│  │  SQLAlchemy    │  │  aiosqlite       │  │  Alembic   │  │
│  │  Async ORM     │  │  (SQLite driver) │  │ migrations │  │
│  └────────────────┘  └──────────────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Component interactions**:
- The Interface Layer accepts user input and delegates to the Orchestration Layer via `WorkflowManager.execute_scan()`.
- The Orchestration Layer dispatches to one or more Adapters, collects results, deduplicates, and persists to the database.
- Each Adapter communicates with its respective external tool (subprocess for Semgrep, HTTP REST for HexStrike) and normalises output to the common schema.
- The Persistence Layer is accessed exclusively through async CRUD functions in `db/crud.py`, isolating the rest of the system from database details.
- The LLM integration (`ai_engine/`) is an optional, post-scan enrichment step invoked only when `--llm-explain` is passed.

---

### B.3 Major Design Decisions and Patterns

| Pattern | Location | Rationale |
|---|---|---|
| **Adapter** | `adapters/adapter_base.py`, `semgrep_adapter.py`, `hexstrike_adapter.py` | Isolates tool-specific logic; allows new tools to be added without modifying core pipeline |
| **Abstract Base Class (ABC)** | `adapters/adapter_base.py` | Enforces `scan()` and `normalize_results()` contract at class definition time; prevents incomplete adapters from being instantiated |
| **Orchestrator / Manager** | `orchestrator/workflow_manager.py` | Single coordination point; decouples interface concerns (CLI/API) from execution concerns |
| **Repository (CRUD)** | `db/crud.py` | Abstracts database access behind named functions; hides SQLAlchemy session management from callers |
| **Configuration Object** | `backend/app/core/config.py` (Pydantic `BaseSettings`) | Centralises all environment-variable-driven settings; validates types at startup; supports `.env` file injection |
| **Strategy (partial)** | `HexStrikeAdapter.normalize_results()` | Per-tool parsing branches within a single method — a lightweight Strategy without full class hierarchy |
| **Dependency Injection** | FastAPI `Depends(get_db)` | Injects async database sessions into endpoint functions; enables easy testing substitution |
| **Value Object** | `schemas/security.py` (Pydantic models) | Immutable, validated data transfer objects crossing layer boundaries |

**SOLID alignment**:
- *Single Responsibility*: `WorkflowManager` coordinates, `ResultMerger` deduplicates, `crud.py` persists — each has one primary concern.
- *Open/Closed*: New adapters extend the abstract base without modifying `WorkflowManager`.
- *Liskov Substitution*: `SemgrepAdapter` and `HexStrikeAdapter` are substitutable where `SecurityToolAdapter` is expected.
- *Interface Segregation*: `adapter_base.py` defines the minimal interface required from all adapters.
- *Dependency Inversion*: `WorkflowManager` depends on the `SecurityToolAdapter` abstraction, not concrete adapter classes.

---

### B.4 Technology Stack

| Technology | Role |
|---|---|
| **Python 3.10+** | Primary implementation language |
| **FastAPI 0.104** | REST API framework; async-native; automatic OpenAPI/Swagger docs generation |
| **Uvicorn 0.24** | ASGI server; serves the FastAPI application |
| **Pydantic v2 / pydantic-settings** | Data validation, serialisation, and settings management |
| **SQLAlchemy 2.0** (async) | ORM for database-agnostic persistence with async session support |
| **aiosqlite 0.19** | Asynchronous SQLite driver; avoids blocking the event loop during database I/O |
| **Alembic 1.13** | Database migration management; versioned schema changes |
| **Loguru 0.7** | Structured logging with coloured output and file rotation |
| **python-dotenv 1.0** | `.env` file loading for local development configuration |
| **Semgrep CLI** | SAST engine; invoked via subprocess; returns JSON-formatted findings |
| **HexStrike Server** | External DAST orchestration server; wraps 30+ tools; communicates via HTTP REST |
| **Ollama / DeepSeek-R1:8b** | Local LLM server for vulnerability explanation generation; accessed via HTTP |
| **argparse** (stdlib) | CLI argument parsing in `security_assistant.py` |
| **asyncio** (stdlib) | Async I/O runtime; subprocess management; thread offloading |
| **Nuclei, SQLMap, FFUF, Nikto, Dalfox, HTTPX, WAFw00f, Gobuster, Dirsearch, Katana, etc.** | DAST tools invoked remotely through HexStrike |
| **Go toolchain** | Required for installing Go-based DAST tools (Nuclei, HTTPX, Gobuster, etc.) |

**Notable absences**: No containerisation (no `Dockerfile` or `docker-compose.yml` present), no CI/CD pipeline configuration (no `.github/workflows/`, `.gitlab-ci.yml`, etc.), no frontend framework (placeholder HTML only).

---

### B.5 Design Documents

No formal UML diagrams, sequence diagrams, or ER diagrams in diagrammatic form are present in the repository. However, the following textual equivalents are present:

- **Architecture overview** (text + ASCII): `CLAUDE.md` and `docs/DISSERTATION_ANALYSIS.md` contain layered ASCII diagrams and data-flow descriptions.
- **ER diagram (textual)**: `docs/DISSERTATION_ANALYSIS.md` describes all nine tables, their columns, and foreign-key relationships in structured prose.
- **Data flow diagrams (textual)**: `CLAUDE.md` contains explicit data-flow sequences for SAST and DAST pipelines.
- **API endpoint table**: `README.md` lists all API endpoints, methods, and descriptions.

---

---

## C. Development of the Artefact

### C.1 Directory Structure and Module Responsibilities

```
security-ai-assistant/
├── security_assistant.py      # CLI entry point; full scan orchestration; HexStrike management
├── backend/
│   └── app/
│       ├── main.py            # FastAPI app; lifecycle events; CORS; route mounting
│       ├── api/v1/
│       │   ├── routers.py     # Router registration; groups endpoints under /api/v1
│       │   └── endpoints/
│       │       └── security.py # POST /scan endpoint; ScanRequest → ScanResponse
│       └── core/
│           ├── config.py      # Pydantic BaseSettings; all env vars with defaults
│           └── security.py    # Path sanitisation; traversal prevention
├── orchestrator/
│   ├── workflow_manager.py    # Central coordinator; validation; adapter dispatch; DB writes
│   └── result_merger.py       # Deduplication by (title, source, file, line) composite key
├── adapters/
│   ├── adapter_base.py        # ABC: tool_name, version, scan(), normalize_results()
│   ├── semgrep_adapter.py     # Semgrep subprocess invocation; JSON parsing; severity mapping
│   └── hexstrike_adapter.py   # HexStrike REST calls; per-tool normalisation (Nuclei, SQLMap, etc.)
├── db/
│   ├── base.py                # SQLAlchemy declarative Base
│   ├── database.py            # Engine; AsyncSessionLocal; init_db(); get_db() dependency
│   ├── models.py              # 9 ORM models: User, Project, Config, Scan, Finding, …
│   └── crud.py                # Async CRUD functions; session-scoped operations
├── schemas/
│   ├── security.py            # Pydantic models: Vulnerability, ScanRequest, ScanResponse
│   └── common.py              # HealthResponse
├── normalizer/
│   ├── vulnerability_normalizer.py  # Standard schema definition; extension point
│   ├── deduplicator.py             # Standalone deduplication utility
│   └── format_converter.py         # JSON output; SARIF/CSV stubs
├── ai_engine/
│   └── __init__.py            # Ollama HTTP call; prompt construction; response parsing
├── scripts/
│   └── install_tools.py       # Tool presence check; multi-method installation
├── alembic/
│   ├── env.py                 # Alembic config; async engine integration
│   └── versions/
│       └── 0001_phase1_tables.py  # Migration: create all 9 tables with indexes
├── semgrep-rules/
│   └── security-best-practices.yml  # Custom Semgrep rules (JWT, localStorage)
├── docs/
│   ├── README.md, USER_GUIDE.md, DEV_GUIDE.md, DISSERTATION_ANALYSIS.md
└── requirements.txt           # 9 pinned Python dependencies
```

---

### C.2 Key Classes and Functions

#### `WorkflowManager.execute_scan()` — `orchestrator/workflow_manager.py`

The central execution method. It accepts a `scan_type` string (`"SAST"`, `"DAST"`, or `"SAST,DAST"`), a target path, and a dictionary of per-tool options. Its logic is:

1. Validate the target path against `SCAN_ROOT` and reject traversal sequences.
2. For DAST, validate the target URL against `DAST_ALLOWLIST`.
3. For each requested tool, instantiate the appropriate adapter and call `scan()`.
4. Merge results from all adapters via `ResultMerger`.
5. Return a structured result dictionary with findings, summary counts, and any per-tool errors.

```python
# orchestrator/workflow_manager.py (simplified)
async def execute_scan(self, scan_type, target_path, options):
    if "SAST" in scan_type:
        self._validate_path(target_path)
        adapter = SemgrepAdapter()
        raw = await adapter.scan(target_path, options)
        findings.extend(adapter.normalize_results(raw))
    if "DAST" in scan_type:
        self._validate_dast_target(options.get("target"))
        adapter = HexStrikeAdapter()
        raw = await adapter.scan(options.get("target"), options)
        findings.extend(adapter.normalize_results(raw))
    merged = ResultMerger().merge_and_deduplicate(findings)
    return {"findings": merged, "summary": {...}, "errors": errors}
```

#### `SecurityToolAdapter` — `adapters/adapter_base.py`

The Abstract Base Class defining the adapter contract. All adapters must implement:

```python
class SecurityToolAdapter(ABC):
    @abstractmethod
    async def scan(self, target_path: str, options: dict) -> List[Dict]:
        """Execute the tool; return raw output."""

    @abstractmethod
    def normalize_results(self, raw_results: List[Dict]) -> List[Dict]:
        """Map raw output to common finding schema."""

    @property
    @abstractmethod
    def tool_name(self) -> str: ...

    @property
    @abstractmethod
    def version(self) -> str: ...
```

This enforces the Adapter pattern: `WorkflowManager` only depends on this interface, not on `SemgrepAdapter` or `HexStrikeAdapter` directly.

#### `SemgrepAdapter.scan()` — `adapters/semgrep_adapter.py`

Invokes Semgrep as a subprocess with `--json` output and exclusion of non-project directories:

```python
proc = await asyncio.create_subprocess_exec(
    "semgrep", "--json", "--config", rule_path, target_path,
    "--exclude", "node_modules", "--exclude", "venv",
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE
)
try:
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
finally:
    if proc.returncode is None:
        proc.kill()
```

The 300-second timeout with explicit `proc.kill()` ensures the process cannot run indefinitely.

#### `HexStrikeAdapter.normalize_results()` — `adapters/hexstrike_adapter.py`

Implements tool-specific normalisation within a single method using per-tool branches:

```python
def normalize_results(self, raw_results):
    tool = raw_results.get("tool")
    stdout = raw_results.get("stdout", "")
    if tool == "nuclei":
        return self._parse_nuclei(stdout)
    elif tool == "sqlmap":
        return self._parse_sqlmap(stdout)
    elif tool == "ffuf":
        return self._parse_ffuf(stdout)
    else:
        return self._parse_raw_fallback(stdout, tool)
```

Nuclei produces structured JSONL that is fully parsed. SQLMap output is processed via keyword detection (`"injection point"`, `"back-end dbms"`). All other tools fall back to a raw-output finding with LOW/INFO severity and confidence 0.3.

#### `generate_explanation_and_fix()` — `ai_engine/__init__.py`

Constructs a structured prompt from a finding dictionary, sends it to the Ollama API, and parses the response:

```python
prompt = f"""
You are a security expert. Analyse this vulnerability:
Title: {finding['title']}
Severity: {finding['severity']}
Description: {finding['description']}
Location: {finding.get('location', {})}

Provide:
[Explanation] Plain-English explanation of the vulnerability
[Fix] Concrete remediation steps
"""
response = requests.post("http://localhost:11434/api/generate",
    json={"model": model, "prompt": prompt, "stream": False},
    timeout=180)
```

#### `_validate_path()` — `orchestrator/workflow_manager.py`

Enforces filesystem safety before any SAST scan:

```python
def _validate_path(self, path: str) -> None:
    if "\x00" in path:
        raise ValueError("Null byte in path")
    if ".." in path:
        raise ValueError("Path traversal detected")
    resolved = Path(path).resolve()
    scan_root = Path(settings.scan_root).resolve()
    if not str(resolved).startswith(str(scan_root)):
        raise PermissionError(f"Path outside SCAN_ROOT: {resolved}")
```

This directly addresses CWE-22 (Path Traversal).

---

### C.3 Version Control and Development Practices

**Git history** (five commits, oldest to newest):
1. `Initial commit: Security AI Assistant project - pre-refactoring state`
2. `Refactor: Align codebase with third-year student profile`
3. `Clean up: Remove files inappropriate for student submission`
4. `Update project structure: add CLI, alembic migrations, semgrep rules, docs`
5. `Add README.md to repo root so GitHub renders it`

**Observations**:
- A single `main` branch is used; no feature branches, pull requests, or tags are present. This is consistent with solo student development.
- Commit messages are descriptive and structured, though not following a formal convention such as Conventional Commits.
- The presence of a "clean up" commit removing files "inappropriate for student submission" indicates awareness of submission requirements.
- No `.gitignore` file is present in the repository (shown as deleted in git status). Its absence may result in accidental committing of environment files.
- No pre-commit hooks, linting configuration (`.flake8`, `pyproject.toml`), or formatting configuration (`black`, `isort`) are present.

**Documentation practices**:
- `README.md` (312 lines) provides setup, usage examples, environment variable reference, and architecture overview.
- `docs/USER_GUIDE.md` provides end-user quick-start examples per tool.
- `docs/DEV_GUIDE.md` provides developer onboarding and extension guidance.
- `docs/DISSERTATION_ANALYSIS.md` provides a project-level analysis for academic review.
- Inline docstrings are present in key modules but are not consistently applied across all files.

---

### C.4 Notable Implementation Techniques

#### Async/Await Throughout
All I/O-bound operations avoid blocking the event loop. Semgrep is launched via `asyncio.create_subprocess_exec()`; HexStrike HTTP calls are wrapped with `asyncio.to_thread()` (since the `requests` library is synchronous); database operations use `AsyncSession`.

#### Multi-Tool Confidence Scoring
Each normalised finding carries a `confidence` float. Nuclei findings (structured, template-verified) receive 0.8. FFUF findings (HTTP status-based) receive 0.6. Raw-fallback findings receive 0.3. This allows consumers to weight findings appropriately.

#### Composite Deduplication Key
The deduplication key `(title, source, file_path, line)` ensures that the same vulnerability found by multiple tools in the same location is reported only once, while preserving distinct findings at different locations.

#### Pydantic Settings with `.env` Support
`backend/app/core/config.py` uses `pydantic-settings` `BaseSettings`, which automatically reads environment variables and an optional `.env` file. This eliminates the need for conditional `os.getenv()` calls throughout the codebase and provides type coercion and default values in one location.

#### Database-Agnostic Async ORM
The SQLAlchemy 2.0 async ORM with aiosqlite means the entire database layer makes no synchronous I/O calls. The `_normalize_async_sqlite_url()` function in `db/database.py` handles legacy `sqlite://` URLs transparently.

#### Path Traversal Prevention (CWE-22)
Input sanitisation in `backend/app/core/security.py:sanitize_path()` and `WorkflowManager._validate_path()` implements defence-in-depth: null bytes are stripped, `..` sequences are rejected, and the resolved absolute path is checked against `SCAN_ROOT`. The two-layer approach means the protection applies to both API and CLI input paths.

#### DAST Authorisation Gate
The `--dast-authorized` flag (CLI) and `DAST_ALLOW_NONLOCAL` environment variable (API) function as explicit user acknowledgement that they have permission to scan the target. Without these, `WorkflowManager._validate_dast_target()` restricts scanning to `localhost` and `127.0.0.1`, preventing the tool from being used for unauthorised scanning.

---

---

## D. Testing and Evaluation of the Artefact

### D.1 Test Inventory

**No automated test files are present in the repository.** The git commit history includes a commit message: `Clean up: Remove files inappropriate for student submission`, and the `docs/DISSERTATION_ANALYSIS.md` explicitly states: *"Unit tests: Removed in latest commit; need re-adding before evaluation."*

The following test-related observations can be made:

| Test Type | Status | Evidence |
|---|---|---|
| Unit tests | Absent | Removed per commit 3; not re-added |
| Integration tests | Absent | No test files found in any directory |
| End-to-end tests | Absent | No test runner configuration present |
| Performance benchmarks | Absent | No benchmark scripts or results |
| Coverage reports | Absent | No `.coverage`, `htmlcov/`, or `pytest.ini` |
| User study data | Absent | No evaluation data files |

No test framework configuration files (`pytest.ini`, `setup.cfg`, `pyproject.toml[tool.pytest]`) are present.

---

### D.2 Analysable Test Coverage (Structural)

Although no automated tests are present, a structural analysis of the codebase allows assessment of which components would require testing and what is currently unverified:

#### Components with High Testability (but currently untested)

**`orchestrator/result_merger.py`**
The `merge_and_deduplicate()` method is a pure function: it takes a list and returns a deduplicated list. It has no I/O dependencies and would be straightforward to unit-test with constructed finding dictionaries.

**`adapters/semgrep_adapter.py:normalize_results()`**
Normalisation logic maps Semgrep JSON to the common schema. With a sample Semgrep JSON fixture, this could be tested without invoking the Semgrep binary.

**`adapters/hexstrike_adapter.py:normalize_results()`**
The per-tool parsing branches (Nuclei JSONL, SQLMap keyword detection, FFUF regex) are deterministic string-processing functions testable with static input fixtures.

**`backend/app/core/security.py:sanitize_path()`**
The path sanitisation function accepts a string and returns a string or raises. This is an ideal unit-test target for security-critical logic: test null bytes, `..` sequences, absolute paths, and valid relative paths.

**`orchestrator/workflow_manager.py:_validate_path()`** and **`_validate_dast_target()`**
Security-critical validation functions with clear pass/fail conditions. These should have explicit test cases for boundary conditions (e.g., path exactly equal to `SCAN_ROOT`, path one level outside, URL exactly on allowlist).

**`db/crud.py`**
CRUD functions could be integration-tested against an in-memory SQLite database.

**`ai_engine/__init__.py:generate_explanation_and_fix()`**
Could be tested with a mock HTTP server replacing Ollama, verifying prompt construction and response parsing.

---

### D.3 Test Doubles and Their Intended Use

No test doubles are present in the repository. Based on the architecture, the following would be required for a comprehensive test suite:

| Component Under Test | Required Double | Type |
|---|---|---|
| `SemgrepAdapter.scan()` | Mock `asyncio.create_subprocess_exec` | Mock |
| `HexStrikeAdapter.scan()` | Mock HTTP server for HexStrike | Stub / Fake server |
| `ai_engine.generate_explanation_and_fix()` | Mock Ollama HTTP endpoint | Stub |
| `db/crud.py` | In-memory async SQLite | Fake |
| `WorkflowManager.execute_scan()` | Mock adapters | Mock |

---

### D.4 Manual Testing Evidence

While no automated tests are present, the following evidence suggests manual testing was performed during development:

- The `docs/USER_GUIDE.md` contains specific, detailed CLI invocation examples with real tool names and flag combinations, suggesting these were executed and verified.
- The `docs/DEV_GUIDE.md` includes a "Local testing examples" section with concrete commands.
- The `README.md` lists "Known Limitations" that are consistent with having run the tool and observed its behaviour (e.g., "SQLite performance adequate for lab use; not production-scale").
- The `_ensure_hexstrike_running()` function in `security_assistant.py` includes a health-check loop with retry logic, suggesting this was developed against a real HexStrike instance.

---

### D.5 Evaluation Against Requirements

The table below maps each functional requirement to its verification status:

| Requirement | Verification Method Available | Status |
|---|---|---|
| FR-01 SAST Scanning | Manual CLI execution + inspect output | Unverified by automated test |
| FR-02 DAST Scanning | Manual CLI execution against test target | Unverified by automated test |
| FR-03 Combined scan | Manual CLI execution | Unverified by automated test |
| FR-04 Multi-tool DAST | Manual inspection of HexStrikeAdapter tool map | Structural evidence present |
| FR-05 Standard schema | Schema defined in `schemas/security.py`; applied in adapters | Structurally verifiable |
| FR-06 Deduplication | `ResultMerger` logic is inspectable | No test verifying correctness |
| FR-07 Persistence | `db/models.py`, `db/crud.py` exist; Alembic migration exists | No integration test |
| FR-08 REST API | Endpoint defined in `security.py`; FastAPI auto-validates | No API-level test |
| FR-09 CLI | Argparse definitions match documented usage | No automated test |
| FR-10 LLM explanations | `ai_engine/__init__.py` implements Ollama call | No test with mock LLM |
| FR-16 Custom Semgrep rules | YAML file present and syntactically valid | No test against sample code |
| FR-20 Security header check | Function in `security_assistant.py` | No automated assertion |
| NFR-01 Async I/O | Code inspection confirms async throughout | No concurrency test |
| NFR-06 Process timeout | Explicit `asyncio.wait_for(timeout=300)` in code | No test verifying kill |
| NFR-07 Graceful degradation | Try/except blocks in `execute_scan()` | No fault-injection test |

---

### D.6 Evaluation Data

No quantitative evaluation data is present in the repository: no performance benchmarks, no accuracy metrics (false-positive/false-negative rates), no latency measurements, and no user study results.

The following observations can be made about what an evaluation would need to demonstrate:

- **Detection accuracy**: The Nuclei adapter would need to be run against a known-vulnerable application (e.g., DVWA, Juice Shop) to measure true-positive rate.
- **False-positive rate**: The raw-fallback parsing in `HexStrikeAdapter` (confidence 0.3) is likely to generate false positives; this would need empirical measurement.
- **LLM explanation quality**: The `ai_engine` output quality would need human evaluation (e.g., expert rating on relevance and correctness of explanations).
- **Scan latency**: No timing instrumentation is present; Semgrep's 300-second timeout provides an upper bound but no nominal performance data.

---

### D.7 Limitations and Untested Aspects

The following limitations are identifiable from the codebase:

1. **No automated test suite**: The absence of tests means all verification is manual or structural. This is the most significant evaluation gap.

2. **Raw fallback normalisation quality**: Approximately 20 of the 30+ DAST tools fall through to the raw-output fallback parser with confidence 0.3. The accuracy and utility of these findings is unknown without empirical evaluation.

3. **No cross-scan deduplication**: Findings are deduplicated only within a single scan run. The same vulnerability appearing in two separate scans will be stored twice in the database. `result_merger.py` does not query historical findings.

4. **SQLite write concurrency**: aiosqlite serialises writes to SQLite. Under concurrent API requests, this becomes a bottleneck. No load testing is present to characterise this.

5. **Ollama model dependency**: The LLM integration requires a separately-running Ollama server with the `deepseek-r1:8b` model pre-pulled. No fallback or degraded-mode path is tested without the server present (the code returns a fallback string, but the quality of that fallback is not evaluated).

6. **HexStrike dependency**: All DAST functionality depends on an external server at `../hexstrike-ai/`. The reliability and behaviour of this server under various error conditions is not tested within the project boundary.

7. **Missing GET endpoints**: The API exposes only `POST /api/v1/security/scan` and `GET /health`. Endpoints for retrieving scan history, individual findings, or project listings are absent (noted as Phase 5 in the roadmap), meaning the persistence layer has no read-path through the API.

8. **No frontend implementation**: The project documentation references a Vue.js dashboard as Phase 9. No frontend code exists at present; the system is entirely CLI/API-driven.

9. **No authentication**: The API has no authentication or authorisation layer. Any caller with network access to port 8000 can trigger scans. This is acknowledged in the roadmap as Phase 6.

10. **No CI/CD pipeline**: Without automated testing and a CI/CD configuration, code quality and regression prevention depend entirely on manual discipline.

---

*Notes on absent artefacts*: The repository does not contain a `Dockerfile`, `docker-compose.yml`, CI/CD pipeline configuration, formal requirements specification, test reports, user study data, or any frontend code. Where these are referenced in documentation as planned but unimplemented, they have been noted as limitations above rather than treated as present features.
