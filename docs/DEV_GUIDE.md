## Developer Guide (Security AI Assistant)

### 1) Architecture Overview

- **CLI**: `security_assistant.py`
- **FastAPI**: `backend/app/main.py`
- **Orchestrator**: `orchestrator/workflow_manager.py`
- **Adapters**: `adapters/semgrep_adapter.py`, `adapters/hexstrike_adapter.py`
- **DB**: `db/` (async SQLAlchemy)
- **Schemas**: `schemas/`

Main flow:
1) CLI/API -> WorkflowManager
2) Adapters run tools
3) Normalize + merge results
4) Persist in SQLite

### 2) Database

- Async SQLite by default
- Tables: `users`, `projects`, `configs`, `scans`, `findings`, `ai_explanations`, `fix_suggestions`, `risk_scores`, `feedback`
- `init_db()` creates tables on startup

### 3) Migrations (Alembic)

Config:
- `alembic.ini`
- `alembic/env.py`
- `alembic/versions/0001_phase1_tables.py`

Usage:
```bash
alembic upgrade head
```

### 4) Adding a New Tool Adapter

1. Implement `SecurityToolAdapter` in `adapters/`.
2. Register it in `WorkflowManager` defaults.
3. Add normalization into `normalize_results()`.

### 5) HexStrike DAST

HexStrike integration is URL-based:
- `HEXSTRIKE_URL` (default: `http://127.0.0.1:4444`)

Adapter maps tool names to endpoints:
```
/api/tools/{tool}
```

Nuclei output parsing is implemented. Other tools store raw output in metadata.

### 6) Safety

- SAST path restricted by `SCAN_ROOT` (API safety)
- CLI can override with `--allow-any-path`
- DAST allowlist enforced unless `DAST_ALLOW_NONLOCAL=true` or `--dast-authorized`

### 7) Local Testing

CLI:
```bash
python3 security_assistant.py --scan SAST --sast-path "backend"
```

DAST (Nuclei):
```bash
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool nuclei --dast-authorized
```

### 8) Known Limitations

- Nuclei is the only DAST tool fully parsed into structured findings.
- Others are stored as INFO findings with raw output in metadata.

