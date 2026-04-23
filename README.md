# Security AI Assistant

**Third-Year Final Project — Liverpool John Moores University (LJMU)**
**Module: Computer Security / Secure Software Development**

---

## Overview

Security AI Assistant is a unified **SAST + DAST** vulnerability scanning pipeline built as part of my third-year project at LJMU. The tool combines two complementary security testing approaches:

- **SAST (Static Application Security Testing)** — scans source code without executing it, using [Semgrep](https://semgrep.dev/) to detect insecure coding patterns (e.g., injection flaws, hardcoded credentials, insecure use of crypto).
- **DAST (Dynamic Application Security Testing)** — actively probes a running application for vulnerabilities, using [HexStrike AI]([(https://github.com/0x4m4/hexstrike-ai)](https://github.com/0x4m4/hexstrike-ai)) as the backend toolchain (Nuclei, SQLMap, Nikto, etc.).

Results from both scanners are normalised into a common finding format, deduplicated, stored in a local SQLite database, and optionally explained by a locally-running LLM (DeepSeek via Ollama).

The project demonstrates skills from the following areas:
- Secure software design and OOP principles
- Web application security (OWASP Top 10)
- REST API development (FastAPI)
- Async programming in Python
- Database design and ORM (SQLAlchemy)

---

## Project Architecture

```
security-ai-assistant/
├── security_assistant.py     # CLI entry point
├── backend/
│   └── app/
│       ├── main.py           # FastAPI application
│       ├── api/v1/
│       │   ├── routers.py    # API route registration
│       │   └── endpoints/
│       │       └── security.py   # /scan endpoint
│       └── core/
│           ├── config.py     # Settings (env vars / .env)
│           └── security.py   # Input sanitisation helpers
├── adapters/
│   ├── adapter_base.py       # Abstract base class for all adapters
│   ├── semgrep_adapter.py    # SAST: Semgrep integration
│   └── hexstrike_adapter.py  # DAST: HexStrike REST integration
├── orchestrator/
│   ├── workflow_manager.py   # Central scan coordinator
│   └── result_merger.py      # Deduplication logic
├── normalizer/
│   ├── vulnerability_normalizer.py  # Common finding schema
│   ├── deduplicator.py              # Duplicate removal
│   └── format_converter.py          # Output format conversion
├── db/
│   ├── models.py             # SQLAlchemy ORM models
│   ├── crud.py               # Database helper functions
│   └── database.py           # Async engine + session factory
├── ai_engine/
│   └── __init__.py           # DeepSeek/Ollama LLM integration
├── schemas/
│   ├── security.py           # Pydantic request/response models
│   └── common.py             # Shared API schemas
└── alembic/                  # Database migration scripts
```

### Data Flow

```
CLI / API
  └──> WorkflowManager.execute_scan()
         ├──> SemgrepAdapter.scan()       → raw SAST findings
         ├──> HexStrikeAdapter.scan()     → raw DAST findings
         ├──> adapter.normalize_results() → common finding shape
         ├──> ResultMerger.merge_and_deduplicate()
         ├──> save_to_db() via db/crud.py → SQLite
         └──> (optional) ai_engine → LLM explanations stored in DB
```

---

## Setup

### Prerequisites

- Python 3.10+
- `semgrep` installed (for SAST)
- HexStrike server running at `../hexstrike-ai/` (for DAST)
- Ollama with DeepSeek model loaded (optional, for LLM explanations)

### Installation

```bash
# Clone and enter the project
cd security-ai-assistant

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Initialise the SQLite database
python3 -c "import asyncio; from db.database import init_db; asyncio.run(init_db())"

# (Optional) Copy environment template and customise
cp env.template .env
```

### Install Security Tools

```bash
bash scripts/install_tools.sh
```

---

## Usage

### CLI (Recommended)

The CLI is the primary way to run scans. It handles tool startup, scanning, result storage, and optional LLM explanations.

#### SAST Only (Static Code Analysis)

```bash
python3 security_assistant.py --scan SAST --sast-path "/path/to/project" --allow-any-path
```

#### DAST Only (Dynamic Web Scanning)

```bash
# Using Nuclei (vulnerability scanner)
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool nuclei --dast-authorized

# Using SQLMap (SQL injection tester)
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool sqlmap --dast-authorized

# Using HTTPX (HTTP probing / fingerprinting)
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool httpx --dast-authorized

# Using Nikto (web server scanner)
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool nikto --dast-authorized
```

#### Combined SAST + DAST

```bash
python3 security_assistant.py \
  --scan SAST,DAST \
  --sast-path "/path/to/project" \
  --dast-target "http://127.0.0.1:3000" \
  --allow-any-path \
  --dast-tool all-web \
  --dast-authorized
```

#### Run All Available DAST Tools

```bash
python3 security_assistant.py \
  --scan DAST \
  --dast-target "http://127.0.0.1:3000" \
  --dast-tool all-web \
  --dast-authorized
```

#### With LLM Explanations (requires Ollama + DeepSeek)

```bash
python3 security_assistant.py \
  --scan SAST \
  --sast-path "/path/to/project" \
  --allow-any-path \
  --llm-explain \
  --llm-max-findings 5
```

---

### REST API (FastAPI)

Start the server:

```bash
uvicorn backend.app.main:app --reload
```

Endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/` | API info |
| `POST` | `/api/v1/security/scan` | Run a scan |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/redoc` | ReDoc UI |

Example API request:

```bash
curl -X POST http://localhost:8000/api/v1/security/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_path": "/path/to/project",
    "tools": ["semgrep"],
    "options": {}
  }'
```

---

## HexStrike Server

HexStrike is a separate server that wraps DAST tools (Nuclei, SQLMap, Nikto, etc.) behind a REST API. It lives at `../hexstrike-ai/` relative to this project.

Start manually:

```bash
cd ../hexstrike-ai
./venv/bin/python3 hexstrike_server.py --port 4444
```

The CLI will auto-start HexStrike if it is not already running. To disable this:

```bash
python3 security_assistant.py --scan DAST ... --no-start-hexstrike
```

---

## Safety Controls

Security scanning tools can cause real harm if misused. This project implements several controls to prevent accidental or unauthorised scanning.

### SAST Safety

| Control | Description |
|---------|-------------|
| `SCAN_ROOT` | Scans are restricted to this directory when using the API. Defaults to `.` (project root). |
| `--allow-any-path` | CLI-only flag to scan directories outside `SCAN_ROOT`. Must be explicit. |
| Path validation | Rejects null bytes and `..` traversal sequences before scanning. |

### DAST Safety

| Control | Description |
|---------|-------------|
| `DAST_ALLOWLIST` | Comma-separated list of allowed DAST target hostnames. Defaults to `localhost,127.0.0.1`. |
| `--dast-authorized` | CLI flag confirming you have permission to scan the target. Required for non-allowlisted targets. |
| `DAST_ALLOW_NONLOCAL` | Environment variable to bypass the allowlist entirely (for lab/testing use). |

> **Note:** Only scan targets you own or have explicit written permission to test. Unauthorised scanning is illegal under the Computer Misuse Act 1990 (UK).

---

## Environment Variables

Copy `env.template` to `.env` and adjust as needed.

| Variable | Default | Description |
|----------|---------|-------------|
| `HEXSTRIKE_URL` | `http://127.0.0.1:4444` | URL of the running HexStrike server |
| `HEXSTRIKE_PATH` | `../hexstrike-ai` | Filesystem path to HexStrike repo (for auto-start) |
| `HEXSTRIKE_API_KEY` | _(empty)_ | API key for HexStrike, if authentication is enabled |
| `SEMGREP_PATH` | `semgrep` | Path to Semgrep binary (defaults to PATH lookup) |
| `SCAN_ROOT` | `.` | Restricts SAST scans to this directory (API safety) |
| `DAST_ALLOWLIST` | `localhost,127.0.0.1` | Comma-separated DAST target allowlist |
| `DAST_ALLOW_NONLOCAL` | `false` | Set to `true` to bypass DAST allowlist |
| `DEEPSEEK_MODEL` | `deepseek-r1:8b` | Ollama model name for LLM explanations |
| `DATABASE_URL` | `sqlite+aiosqlite:///./security_assistant.db` | SQLite database path |
| `API_HOST` | `0.0.0.0` | FastAPI bind address |
| `API_PORT` | `8000` | FastAPI bind port |
| `API_DEBUG` | `false` | Enable debug mode and verbose logging |

---

## Database Migrations

This project uses Alembic for database migrations.

```bash
# Apply all pending migrations
alembic upgrade head

# Create a new migration after model changes
alembic revision --autogenerate -m "describe the change"
```

---

## Known Limitations

- Only **Nuclei** produces fully structured DAST findings. Other tools (SQLMap, Nikto, etc.) are parsed on a best-effort basis; unparsed output is stored as `INFO`-severity findings for review.
- The `all-web` mode queries HexStrike's `/health` endpoint to determine which tools are installed before running them.
- LLM explanations require a locally running Ollama instance with the DeepSeek model pulled (`ollama pull deepseek-r1:8b`).

---

## Security Concepts Referenced

This project demonstrates understanding of the following security topics:

- **OWASP Top 10** (2021): A01 Broken Access Control, A03 Injection, A05 Security Misconfiguration, A07 Identification and Authentication Failures
- **CWE** identifiers are captured per finding where available (e.g., CWE-89 SQL Injection, CWE-79 XSS)
- **Path traversal** prevention (OWASP A03:2021 — Injection)
- **Security headers** checking (CSP, HSTS, X-Frame-Options, etc.)
- **Rate limiting** detection

---
## Acknowledgements

- [Semgrep](https://semgrep.dev/) – fast, open‑source static analysis engine
- [HexStrike AI]([(https://github.com/0x4m4/hexstrike-ai)](https://github.com/0x4m4/hexstrike-ai)) – REST API wrapper for DAST tools (Nuclei, SQLMap, Nikto, etc.)
- [Ollama](https://ollama.ai/) – local LLM runtime for DeepSeek explanations
- All other open‑source libraries listed in `requirements.txt`
---

## Author

Liverpool John Moores University — BSc Computer Security, Year 3 Final Project
