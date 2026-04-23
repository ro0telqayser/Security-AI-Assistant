# Security AI Assistant — Dissertation Analysis

## 1. Project Overview & Purpose

Your project is a **unified security scanning pipeline** that combines:
- **SAST** (Static Application Security Testing) via **Semgrep**
- **DAST** (Dynamic Application Security Testing) via **HexStrike** (which proxies 30+ tools: Nuclei, SQLMap, FFuf, Nikto, Dalfox, etc.)
- **AI-powered explanations** via a local LLM (DeepSeek through Ollama)
- A **FastAPI REST backend** with async SQLite persistence
- A **CLI interface** for direct terminal use

The goal: give developers a single tool that covers the full vulnerability detection lifecycle — from static code analysis to live web application probing — with AI-generated explanations to make findings actionable.

---

## 2. Architecture

### Layered Architecture (5 Layers)

```
┌─────────────────────────────────────────┐
│  Interface Layer                        │
│  CLI (security_assistant.py)            │
│  FastAPI REST API (backend/app/main.py) │
│  Frontend placeholder (index.html)      │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  Orchestration Layer                    │
│  WorkflowManager (workflow_manager.py)  │
│  ResultMerger (result_merger.py)        │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  Adapter Layer                          │
│  SecurityToolAdapter (ABC)              │
│  SemgrepAdapter / HexStrikeAdapter      │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  External Tools                         │
│  Semgrep CLI / HexStrike REST API       │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  Persistence Layer                      │
│  Async SQLAlchemy ORM + aiosqlite       │
│  Alembic migrations                     │
└─────────────────────────────────────────┘
```

### Data Flow — SAST

1. User runs: `security_assistant.py --scan SAST --sast-path ./myapp`
2. `WorkflowManager._validate_path()` enforces `SCAN_ROOT` boundary (prevents traversal)
3. `SemgrepAdapter.scan()` executes `semgrep --config auto --json --quiet <path>`
4. JSON output normalized → standard `Vulnerability` schema
5. `ResultMerger` deduplicates by `(source, title, file_path, line)` tuple
6. Results saved to DB via `crud.create_scan()` + `crud.add_findings()`

### Data Flow — DAST

1. User runs: `security_assistant.py --scan DAST --dast-target http://localhost --dast-tool nuclei`
2. `WorkflowManager._validate_dast_target()` checks against `DAST_ALLOWLIST`; external targets require `--dast-authorized`
3. `HexStrikeAdapter` POSTs to `http://hexstrike:4444/api/tools/nuclei`
4. HexStrike executes the real tool server-side, returns stdout/JSON
5. Adapter parses output (JSONL for Nuclei; heuristic/regex for others)
6. Normalized findings → merged → stored

---

## 3. What Has Been Implemented

### Fully Implemented

| Component | File(s) | Key Detail |
|---|---|---|
| CLI | `security_assistant.py` | All scan types, 30+ tool flags, auto-start HexStrike, `--llm-explain` |
| WorkflowManager | `orchestrator/workflow_manager.py` | Full orchestration, path/target validation, DB persistence |
| SemgrepAdapter | `adapters/semgrep_adapter.py` | Real subprocess execution, JSON parsing, full normalization |
| HexStrikeAdapter | `adapters/hexstrike_adapter.py` | REST integration for 30+ tools; Nuclei fully parsed, others raw |
| Database ORM | `db/models.py`, `db/database.py` | 9 tables, async SQLAlchemy, aiosqlite, dependency injection |
| CRUD helpers | `db/crud.py` | create/complete scan, add findings, get by ID |
| Alembic migrations | `alembic/versions/0001_...py` | Phase 1 schema with indexes |
| Pydantic schemas | `schemas/security.py` | `ScanRequest`, `ScanResponse`, `Vulnerability`, `VulnerabilityLocation` |
| FastAPI skeleton | `backend/app/main.py` | CORS, startup events, `/health`, `/api/v1/security/scan` |
| Config management | `backend/app/core/config.py` | Pydantic `BaseSettings`, env-driven, 15+ settings |
| ResultMerger | `orchestrator/result_merger.py` | Dedup by 4-tuple key |
| Runtime checks | `security_assistant.py` | Security header analysis (CSP, HSTS, X-Frame-Options), rate limit probing |

### Partially Implemented

| Component | Status | What's There | What's Missing |
|---|---|---|---|
| HexStrike parsing | 80% | Nuclei: full JSONL parse. SQLMap: heuristic. FFuf: regex. Nikto/Dalfox: line scan | 20+ tools stored as raw `INFO` output only |
| AI Engine | 20% | Ollama subprocess call scaffold, prompt template, delimiter parsing | Real Ollama server integration, error recovery, quality evaluation |
| FastAPI endpoints | 60% | POST `/scan` works end-to-end | No GET endpoints for retrieval, no auth, no projects/configs API |

### Skeleton / Placeholder

| Component | File | Note |
|---|---|---|
| VulnerabilityNormalizer | `normalizer/vulnerability_normalizer.py` | Returns input unchanged |
| Deduplicator class | `normalizer/deduplicator.py` | No-op method; real dedup is in ResultMerger |
| FormatConverter | `normalizer/format_converter.py` | Only `json.dumps()` — no SARIF, XML, CSV |
| Frontend | `frontend/index.html` | Single placeholder HTML page |

---

## 4. What Still Needs to Be Built

### Phase 5 — REST API Expansion
- `GET /api/v1/scans/{scan_id}` — retrieve a past scan
- `GET /api/v1/scans/{scan_id}/findings` — list findings for a scan
- `GET /api/v1/findings/{finding_id}` — single finding detail
- `GET /api/v1/findings/{finding_id}/explanations` — AI explanations

### Phase 6 — Authentication & Project Management
- JWT or API key authentication
- User/project/config CRUD endpoints
- Role-based access control (RBAC)

### Phase 7 — Normalizer & Enhanced Parsing
- Real `VulnerabilityNormalizer`: CWE mapping, OWASP categorisation, cross-tool severity calibration
- Full structured parsing for FFuf, Nikto, Dalfox, SQLMap, WAFw00f, etc.
- Cross-scan deduplication (same vuln found in two separate scans)
- SARIF/XML/CSV export in `FormatConverter`

### Phase 8 — AI Engine
- Production Ollama/DeepSeek integration
- Explanation quality scoring
- Fix suggestion with code patch generation
- Risk scoring logic (the `risk_scores` table exists but has no logic feeding it)
- User feedback loop (`feedback` table exists but no collection endpoints)

### Phase 9 — Frontend
- Vue.js dashboard (was planned but removed)
- Real-time scan progress via WebSockets
- Finding visualisation, severity filters, trend charts

### Phase 10+ — Advanced
- CI/CD integration (GitHub Actions / GitLab CI webhook triggers)
- ML-based false positive reduction
- Historical trend analysis across scans
- Custom Semgrep rule management (`semgrep-rules/` directory is empty)

---

## 5. Database Schema

9 tables covering the full lifecycle:

```
users ──────────── projects ──────── configs
                       │
                     scans ─────────────────────────────────┐
                       │                                    │
                   findings ──── ai_explanations            │
                       │     ──── fix_suggestions     (FK scan_id)
                       │     ──── risk_scores
                       └──── feedback (FK user_id)
```

### Table Definitions

| Table | Key Columns | Notes |
|---|---|---|
| `users` | id, email (unique), display_name, is_active, created_at | — |
| `projects` | id, owner_id (FK), name, description; Unique(owner_id, name) | Cascade deletes to scans |
| `configs` | id, project_id (FK), name, tools (JSON), options (JSON); Unique(project_id, name) | Saved scan profiles |
| `scans` | id, scan_id (unique), project_id (FK), target_path, tools (JSON), options (JSON), status, error, timestamps | status: pending/completed/failed |
| `findings` | id, scan_id (FK), external_id, source, severity, title, description, file_path, line, column, cwe_id, owasp_category, confidence, location (JSON), metadata (JSON) | Composite index on (scan_id, source, severity) |
| `ai_explanations` | id, finding_id (FK), model, explanation (text), metadata (JSON) | — |
| `fix_suggestions` | id, finding_id (FK), model, suggestion (text), patch (text), metadata (JSON) | — |
| `risk_scores` | id, finding_id (FK), score (float), rationale (text), metadata (JSON) | Logic not yet implemented |
| `feedback` | id, finding_id (FK), user_id (FK), rating (int 1-5), comment (text), metadata (JSON) | No collection endpoints yet |

Notable design choices:
- `tools` and `options` stored as **JSON columns** — flexible, no schema migration needed per new tool
- `findings` has composite index on `(scan_id, source, severity)` — optimised for the most common query pattern
- `Scan.status` field tracks `pending` → `completed`/`failed` lifecycle
- `Finding.external_id` enables deduplication against a tool's own ID

---

## 6. API Endpoints

### Current Endpoints

| Method | Endpoint | Status | Purpose |
|---|---|---|---|
| GET | `/` | Implemented | Root info + links |
| GET | `/health` | Implemented | Service health check |
| POST | `/api/v1/security/scan` | Implemented | Execute SAST/DAST scan |

### Missing Endpoints (Phase 5+)

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/scans/{scan_id}` | Retrieve past scan |
| GET | `/api/v1/scans/{scan_id}/findings` | List findings for a scan |
| GET | `/api/v1/findings/{finding_id}` | Single finding detail |
| GET | `/api/v1/findings/{finding_id}/explanations` | AI explanations |
| POST | `/api/v1/projects` | Create project |
| GET | `/api/v1/projects/{project_id}/configs` | List saved configs |
| POST | `/api/v1/projects/{project_id}/configs` | Save scan config |
| POST | `/api/v1/auth/token` | Authentication |

---

## 7. Security Scanning Tools Integration

### SAST

| Tool | Execution | Config | Parsing | Status |
|---|---|---|---|---|
| Semgrep | `subprocess` (local binary) | `--config auto` or custom rules | JSON fully parsed | Real execution |

### DAST (via HexStrike REST)

| Tool | Endpoint | Parsing | Confidence |
|---|---|---|---|
| Nuclei | `/api/tools/nuclei` | Full JSONL parsing | 0.8 |
| SQLMap | `/api/tools/sqlmap` | Heuristic string detection | 0.85 |
| FFuf | `/api/tools/ffuf` | Regex (status/lines/words) | 0.6 |
| Nikto | `/api/tools/nikto` | Line-by-line `+ ` prefix | 0.5 |
| Dalfox | `/api/tools/dalfox` | `VULN`/`POC` string scan | 0.6 |
| WAFw00f, HTTPX, Katana, Gobuster, Dirsearch, etc. | `/api/tools/{tool}` | Raw stdout as INFO finding | 0.3 |

### Runtime Checks (CLI)

- Security header presence: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Rate limiting detection: 8-request burst, checks for HTTP 429

---

## 8. Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Language | Python | 3.7+ |
| Web framework | FastAPI | 0.104.0 |
| ASGI server | Uvicorn | 0.24.0 |
| Validation | Pydantic v2 | 2.5.0 |
| ORM | SQLAlchemy | 2.0.23 |
| Database | SQLite (async) | via aiosqlite 0.19.0 |
| Migrations | Alembic | 1.13.1 |
| Logging | Loguru | 0.7.2 |
| SAST | Semgrep | CLI binary |
| DAST orchestrator | HexStrike | Custom REST server |
| LLM backend | Ollama + DeepSeek | External service |

---

## 9. Design Patterns Used

| Pattern | Where Applied |
|---|---|
| **Adapter** | `SecurityToolAdapter` ABC + `SemgrepAdapter`, `HexStrikeAdapter` |
| **Abstract Base Class** | Enforces `scan()` + `normalize_results()` + `tool_name` contract on all adapters |
| **Manager / Orchestrator** | `WorkflowManager` coordinates adapters, normalizer, merger, DB |
| **Dependency Injection** | `WorkflowManager.__init__` accepts custom adapters; FastAPI `get_db()` generator |
| **Layered Architecture** | 5 distinct layers with clear boundaries and one-directional dependencies |
| **Repository / CRUD** | `db/crud.py` abstracts all DB access from business logic |
| **Configuration Object** | Pydantic `BaseSettings` with cascading env var + `.env` file loading |
| **Strategy (partial)** | Different normalisation paths per tool type within HexStrikeAdapter |
| **Async I/O** | All DB + tool execution is `async/await` — non-blocking pipeline |

---

## 10. Security Controls Built Into the System

| Control | Implementation | OWASP / CWE Relevance |
|---|---|---|
| Path traversal prevention | `_validate_path()` rejects `..` and enforces `SCAN_ROOT` | OWASP A03:2021, CWE-22 |
| DAST target allowlist | `_validate_dast_target()` with `DAST_ALLOWLIST`; external targets need `--dast-authorized` | Prevents SSRF, unauthorised scanning |
| Process timeout | 300s limit on Semgrep subprocess with `process.kill()` | DoS prevention |
| Input validation | Pydantic schemas reject malformed requests at the API boundary | OWASP A03, input sanitisation |
| Environment-driven secrets | `HEXSTRIKE_URL`, `DATABASE_URL` in `.env` — not hardcoded | Secrets management best practice |
| Graceful failure | LLM/DB errors don't crash the scan; fallback to partial results | Availability / fault tolerance |

---

## 11. Implementation Status Summary

| Component | Completeness | Notes |
|---|---|---|
| CLI | 100% | All scan types, tool options, safety controls |
| FastAPI skeleton | 90% | /scan endpoint works; GET endpoints missing |
| WorkflowManager | 95% | Full orchestration; normalizer is stub |
| SemgrepAdapter | 100% | Real CLI execution + normalization |
| HexStrikeAdapter | 80% | Real REST integration; only Nuclei fully parsed |
| Database | 100% | Async ORM, migrations, CRUD helpers |
| ResultMerger | 100% | Deduplication by (source, title, file_path, line) |
| VulnerabilityNormalizer | 10% | Placeholder only |
| Deduplicator class | 5% | No-op; dedup lives in ResultMerger |
| AI Engine | 20% | Ollama scaffold; requires external server |
| Frontend | 0% | Single placeholder HTML file |
| Alembic migrations | 100% | Phase 1 schema fully defined |

---

## 12. Dissertation Chapter Outline

### Chapter 1 — Introduction
- Problem: fragmented security tooling landscape; developers face alert fatigue from siloed SAST/DAST tools
- Aim: unified pipeline with AI-assisted triage
- Scope: SAST (Semgrep) + DAST (HexStrike/Nuclei/etc.) + LLM explanations + REST API + CLI

### Chapter 2 — Background & Literature Review
- SAST vs DAST: definitions, trade-offs, complementarity
- Existing tools: Semgrep, SonarQube, OWASP ZAP, Burp Suite, Nuclei — positioning your system
- AI in security: LLM-based vulnerability explanation (GPT-4, DeepSeek), CodeBERT, BERT-based classifiers
- OWASP Top 10 — as the vulnerability classification framework underpinning this system
- Related work: commercial platforms (Snyk, Veracode), open-source pipelines

### Chapter 3 — Requirements & Design
- Functional requirements: scan SAST targets, scan DAST targets, store results, generate AI explanations
- Non-functional requirements: async performance, extensibility (adapter pattern), safety controls
- Architecture decision: why layered + adapter pattern (extensibility, testability, separation of concerns)
- Database design: entity-relationship diagram with justification for async SQLite
- API design: RESTful, Pydantic validation, FastAPI rationale

### Chapter 4 — Implementation
- CLI: argument parsing, safety controls, tool orchestration
- WorkflowManager: path validation logic, DAST authorization enforcement, async execution
- SemgrepAdapter: subprocess management, JSON parsing, normalization mapping
- HexStrikeAdapter: REST proxy design, tool-specific payload construction, Nuclei JSONL parsing vs raw fallback
- Database: async SQLAlchemy patterns, Alembic migration strategy, CRUD abstraction
- AI Engine: Ollama integration, prompt engineering, delimiter-based response parsing
- Security controls in the system itself (path traversal, DAST allowlist)

### Chapter 5 — Testing & Evaluation
- Unit testing: adapter normalization functions, path validation
- Integration testing: end-to-end scan → DB → API flow
- Tool accuracy evaluation: false positive rates across Semgrep/Nuclei
- AI explanation quality: subjective scoring or BLEU-style metric
- Performance: scan time benchmarks, DB query performance

### Chapter 6 — Discussion
- What works well: clean architecture, real tool integration, safety controls
- Limitations: partial DAST parsing (25+ tools raw output only), no frontend, no auth
- Skeleton components and phase roadmap
- Scalability path: SQLite → PostgreSQL, WebSockets for real-time updates, CI/CD webhook integration
- Ethical considerations: responsible disclosure, authorized testing only, DAST allowlist enforcement

### Chapter 7 — Conclusion
- What was achieved vs. original aims
- Contribution: unified SAST+DAST pipeline with AI triage, extensible adapter architecture
- Future work: Phases 5–10 roadmap

---

## 13. Key Technical Claims to Support in the Dissertation

1. **"Adapter pattern enables tool-agnostic extensibility"** — adding a new tool requires only implementing `SecurityToolAdapter` with `scan()` and `normalize_results()`; the rest of the pipeline picks it up automatically.

2. **"Async architecture enables non-blocking I/O for long-running security scans"** — Semgrep on a large codebase can take minutes; async ensures the API remains responsive and DB writes don't block.

3. **"Defence-in-depth applied to the scanner itself"** — path traversal prevention + DAST allowlist + process timeouts + Pydantic validation create multiple independent safety layers.

4. **"Unified schema bridges SAST and DAST output heterogeneity"** — the `Vulnerability` schema with `VulnerabilityLocation` (covering both `file_path/line/column` for SAST and `url/endpoint/parameter` for DAST) is the central design artefact that makes cross-tool comparison possible.

5. **"LLM integration is loosely coupled"** — the AI engine is entirely optional and fails gracefully; the scan pipeline functions completely without it.

---

## 14. Known Limitations & Caveats

1. **SQLite Performance** — Async SQLite adequate for development/student use; not production-scale
2. **Nuclei-Only Full Parsing** — Other DAST tools' output stored raw in metadata (Phase 7 TODO)
3. **No Deduplication Across Scans** — Only within a single scan run
4. **Static Configuration** — No saved "scan profiles" persisted across CLI sessions
5. **Ollama Requirement** — AI engine requires external Ollama server (not bundled)
6. **HexStrike Dependency** — DAST requires a running HexStrike server
7. **No Result Caching** — Each scan re-runs tools even if the same target was scanned before
8. **Tests Removed** — Unit + integration tests were cleaned up in latest commit; need re-adding before evaluation
