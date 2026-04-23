#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEXSTRIKE_DIR="${ROOT_DIR}/../hexstrike-ai"

echo "[*] Installing Semgrep into current venv (if active)..."
python3 -m pip install --upgrade semgrep

echo "[*] Preparing HexStrike AI in ${HEXSTRIKE_DIR}"
if [ ! -d "${HEXSTRIKE_DIR}" ]; then
  echo "ERROR: hexstrike-ai folder not found at ${HEXSTRIKE_DIR}"
  echo "Please clone or place HexStrike AI there."
  exit 1
fi

if [ ! -d "${HEXSTRIKE_DIR}/venv" ]; then
  echo "[*] Creating venv for HexStrike..."
  python3 -m venv "${HEXSTRIKE_DIR}/venv"
fi

echo "[*] Installing HexStrike dependencies..."
"${HEXSTRIKE_DIR}/venv/bin/python3" -m pip install -r "${HEXSTRIKE_DIR}/requirements.txt"

echo "[*] Done. You can start HexStrike with:"
echo "    cd ${HEXSTRIKE_DIR} && ./venv/bin/python3 hexstrike_server.py --port 4444"
