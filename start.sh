#!/usr/bin/env bash
# ./start.sh          run Sthir. Finds other Sthir phones on the same WiFi by itself,
#                     and reads the public node list (seeds.txt) so it joins the same chain.
# ./start.sh solo     this phone only: two nodes, nobody else can connect
cd "$(dirname "$0")"
. ./rules.env
. ./lib.sh
begin
if [ "$1" = "solo" ]; then
  nohup python3 sthir_net.py node --port $NP --host 127.0.0.1 $(miner_arg) --data sthir-data/node1 $RULES > logs/node1.log 2>&1 &
  echo $! > logs/node1.pid
  sleep 1
  nohup python3 sthir_net.py node --port $((NP+1)) --host 127.0.0.1 --peer http://127.0.0.1:$NP --data sthir-data/node2 $RULES > logs/node2.log 2>&1 &
  echo $! > logs/node2.pid
  start_ui
  sleep 2
  echo "Sthir is running (solo: 2 nodes + wallet). Other phones cannot connect."
else
  IP=$(lan_ip)
  nohup python3 sthir_net.py node --port $NP --host 0.0.0.0 --advertise http://$IP:$NP --discover --seeds-url "$SEEDS_URL" $(miner_arg) $(seed_args) --data sthir-data/node1 $RULES > logs/node1.log 2>&1 &
  echo $! > logs/node1.pid
  start_ui
  sleep 2
  echo "Sthir is running and looking for other Sthir phones on this WiFi and in seeds.txt."
  echo "This node: http://$IP:$NP   (other phones need no setup; they find it themselves)"
  echo "Check the Network tab in the wallet for the number of peers."
  echo "Anyone on this WiFi can connect to this node. Use a WiFi you trust, or ./start.sh solo."
fi
echo "Open in your browser: http://127.0.0.1:$UP"
