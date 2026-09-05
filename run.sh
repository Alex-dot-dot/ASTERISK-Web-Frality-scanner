#!/bin/bash
# ============================================================
#  WSCAN  — Web Weakness Scanner launcher
#  Built by NEXO-TECH   •   Running on ASTERISK OS
# ============================================================

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'   # No Color

# Find the Python file next to this script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/wscan.py"

if [ ! -f "$PY" ]; then
    echo -e "${RED}[!] wscan.py not found in $DIR${NC}"
    exit 1
fi

# Check Python exists
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] python3 not found. Install Python 3 first.${NC}"
    exit 1
fi

# Auto-install requests if missing
if ! python3 -c "import requests" &>/dev/null; then
    echo -e "${YELLOW}[*] Installing 'requests' library...${NC}"
    pip install requests || { echo -e "${RED}[!] install failed${NC}"; exit 1; }
fi

echo -e "${CYAN}"
echo "  ==============================================="
echo "   WSCAN launcher  —  NEXO-TECH / ASTERISK OS"
echo "  ==============================================="
echo -e "${NC}"

# No args -> interactive; with args -> CLI mode (passes everything through)
if [ "$#" -eq 0 ]; then
    python3 "$PY"
else
    python3 "$PY" "$@"
fi
