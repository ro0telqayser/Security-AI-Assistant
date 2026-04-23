## User Guide (Security AI Assistant)

This guide is for running scans via the CLI and understanding outputs.

### 1) Quick Start (CLI)

SAST only (Semgrep):
```bash
python3 security_assistant.py --scan SAST --sast-path "/path/to/project" --allow-any-path
```

DAST only (HexStrike Nuclei):
```bash
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool nuclei --dast-authorized
```

SAST + DAST together:
```bash
python3 security_assistant.py \
  --scan SAST,DAST \
  --sast-path "/path/to/project" \
  --dast-target "http://127.0.0.1:3000" \
  --allow-any-path \
  --dast-tool all-web \
  --dast-authorized
```

### 2) DAST Tools (One by One)

```bash
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool nuclei --dast-authorized
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool httpx --dast-authorized
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool wafw00f --dast-authorized
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool sqlmap --dast-authorized
```

Run all available web tools (installed + URL-safe):
```bash
python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool all-web --dast-authorized
```

### 3) SQLMap (Authenticated / Parameterized)

```bash
python3 security_assistant.py \
  --scan DAST \
  --dast-tool sqlmap \
  --dast-target "http://localhost:1337/lab/sql-injection/find-password/?search=12ksad" \
  --sqlmap-cookies "PHPSESSID=YOURSESSION; security=low" \
  --sqlmap-level 3 --sqlmap-risk 2 \
  --dast-authorized
```

Optional:
```bash
--sqlmap-data "a=1&b=2"
--sqlmap-headers "User-Agent: Mozilla/5.0"
--sqlmap-args "--batch --flush-session"
```

### 4) Terminal Output

After each scan, findings print in the terminal:
```
Findings:
- [HIGH] hexstrike: SQL Injection (sqlmap) @ http://localhost:1337/...
- [LOW] semgrep: javascript.express.log.console-log-express.console-log-express @ server/routes.ts:240
```

### 5) Safety Controls

SAST:
- `SCAN_ROOT` limits filesystem scans (API safety)
- CLI can override with `--allow-any-path`

DAST:
- Default allowlist: `localhost,127.0.0.1`
- For external targets:
  - add to `DAST_ALLOWLIST` or set `DAST_ALLOW_NONLOCAL=true`
  - pass `--dast-authorized`

### 6) HexStrike Server

Start HexStrike server:
```bash
cd ../hexstrike-ai
./venv/bin/python3 hexstrike_server.py --port 4444
```

Ensure:
```
HEXSTRIKE_URL=http://127.0.0.1:4444
```

### 7) Troubleshooting

- **No findings**: try a different tool or pass proper parameters/cookies.
- **Tool not installed**: HexStrike `/health` shows availability.
- **403/404 errors**: HexStrike server not running or wrong port.

