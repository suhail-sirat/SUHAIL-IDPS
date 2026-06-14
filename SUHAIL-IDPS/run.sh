#!/usr/bin/env bash
# Launch the SUHAIL-IDPS dashboard backend (serves the UI + API).
#
#   ./run.sh                      # http://localhost:5000
#   IDPS_PORT=8080 ./run.sh       # custom port
#   sudo ./run.sh                 # required for LIVE capture + iptables blocking
#
# Live capture and real iptables enforcement need root. Dataset replay and the
# whole dashboard work fine without root.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PY="${PYTHON:-python}"
PORT="${IDPS_PORT:-5000}"

echo "SUHAIL-IDPS starting on http://localhost:${PORT}"
echo "  (Ctrl+C to stop. Use sudo for live capture / blocking.)"
exec "$PY" dashboard/backend/app.py
