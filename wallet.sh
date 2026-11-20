#!/usr/bin/env bash
# ./wallet.sh                 use the wallet with a node found on this WiFi or in seeds.txt
# ./wallet.sh <node address>  use the wallet with that node
# No node and no mining run on this phone. Your keys stay on this phone.
# Mining on/off is not available here, since the node is not yours.
cd "$(dirname "$0")"
. ./rules.env
. ./lib.sh
NODE="$1"
if [ -z "$NODE" ]; then
  echo "Looking for a Sthir node (about 12 seconds)..."
  NODE=$(python3 sthir_net.py discover --seeds-url "$SEEDS_URL")
  [ -n "$NODE" ] || { echo "No node found. Start Sthir on another phone on this WiFi, or give an address: ./wallet.sh http://IP:5001"; exit 1; }
fi
case "$NODE" in http://*|https://*) ;; *) echo "The address must start with http:// or https://"; exit 1;; esac
./stop.sh >/dev/null 2>&1
mkdir -p logs
nohup python3 sthir_ui.py --node "$NODE" --key wallet.key --port $UP > logs/ui.log 2>&1 &
echo $! > logs/ui.pid
sleep 2
echo "Wallet is using the node at $NODE"
echo "Open in your browser: http://127.0.0.1:$UP"
