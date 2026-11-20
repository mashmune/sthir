#!/usr/bin/env bash
# ./wallet.sh <node address>   use the wallet WITHOUT running a node or mining here.
# Example: ./wallet.sh https://something.trycloudflare.com   or   ./wallet.sh http://192.168.1.5:5001
# Your keys stay on this phone. Mining on/off is not available, since the node is not yours.
cd "$(dirname "$0")"
. ./lib.sh
if [ -z "$1" ]; then echo "Usage: ./wallet.sh <node address>"; exit 1; fi
case "$1" in http://*|https://*) ;; *) echo "The address must start with http:// or https://"; exit 1;; esac
./stop.sh >/dev/null 2>&1
mkdir -p logs
nohup python3 sthir_ui.py --node "$1" --key wallet.key --port $UP > logs/ui.log 2>&1 &
echo $! > logs/ui.pid
sleep 2
echo "Wallet is using the node at $1"
echo "Open in your browser: http://127.0.0.1:$UP"
