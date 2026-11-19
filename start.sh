#!/usr/bin/env bash
# ./start.sh          run on this phone only (2 nodes + wallet page)
# ./start.sh share    also let other phones on the same WiFi join this node
cd "$(dirname "$0")"
. ./rules.env
. ./lib.sh
begin
if [ "$1" = "share" ]; then
  IP=$(lan_ip)
  nohup python3 sthir_net.py node --port $NP --host 0.0.0.0 --advertise http://$IP:$NP $(miner_arg) --data sthir-data/node1 $RULES > logs/node1.log 2>&1 &
  echo $! > logs/node1.pid
  start_ui
  sleep 2
  echo "Sthir is running and sharing on this WiFi."
  echo "On another phone (Sthir installed there too), run:"
  echo "  cd ~/sthir && ./join.sh http://$IP:$NP"
  echo "Share only on a WiFi you trust. Nodes have no passwords."
else
  nohup python3 sthir_net.py node --port $NP --host 127.0.0.1 $(miner_arg) --data sthir-data/node1 $RULES > logs/node1.log 2>&1 &
  echo $! > logs/node1.pid
  sleep 1
  nohup python3 sthir_net.py node --port $((NP+1)) --host 127.0.0.1 --peer http://127.0.0.1:$NP --data sthir-data/node2 $RULES > logs/node2.log 2>&1 &
  echo $! > logs/node2.pid
  start_ui
  sleep 2
  echo "Sthir is running (2 nodes + wallet)."
fi
echo "Open in your browser: http://127.0.0.1:$UP"
