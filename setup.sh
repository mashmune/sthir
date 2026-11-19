#!/usr/bin/env bash
# One command setup after cloning:  ./setup.sh
cd "$(dirname "$0")"
if command -v pkg >/dev/null 2>&1; then pkg install -y python python-cryptography; fi
python3 -c "import cryptography" 2>/dev/null || python3 -m pip install --user cryptography
chmod +x *.sh
python3 -m unittest 2>&1 | tail -3
./start.sh
echo
echo "Open the page above, create a profile (name + password), then back it up from More > Account."
echo "Stop:  ./stop.sh     Start again:  ./start.sh"
