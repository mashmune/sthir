#!/usr/bin/env bash
# ./join.sh http://<host-phone-ip>:5001   join the network of another phone
cd "$(dirname "$0")"
. ./rules.env
. ./lib.sh
if [ -z "$1" ]; then
  echo "Usage: ./join.sh http://<host-phone-ip>:5001"
  echo "The host phone prints this address when it runs: ./start.sh share"
  exit 1
fi
begin
IP=$(lan_ip)
# A separate data folder, so an old solo chain can never overwrite the network's chain.
nohup python3 sthir_net.py node --port $NP --host 0.0.0.0 --advertise http://$IP:$NP --peer "$1" --discover --seeds-url "$SEEDS_URL" $(seed_args) $(miner_arg) --data sthir-data/joined $RULES > logs/node1.log 2>&1 &
echo $! > logs/node1.pid
start_ui
sleep 2
echo "Joined $1."
echo "Open in your browser: http://127.0.0.1:$UP"
