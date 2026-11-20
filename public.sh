#!/usr/bin/env bash
# ./public.sh   put this phone's node on the internet, so phones anywhere can join it.
# Uses a free Cloudflare quick tunnel. The address changes every time you run this.
# Friends join with:  ./join.sh <the https address printed below>
cd "$(dirname "$0")"
. ./rules.env
. ./lib.sh
if ! command -v cloudflared >/dev/null 2>&1; then
  echo "Installing cloudflared (one time)..."
  pkg install -y cloudflared || { echo "Could not install cloudflared."; exit 1; }
fi
begin
rm -f logs/tunnel.log
nohup cloudflared tunnel --no-autoupdate --url http://127.0.0.1:$NP > logs/tunnel.log 2>&1 &
echo $! > logs/tunnel.pid
URL=""
for i in $(seq 1 40); do
  URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' logs/tunnel.log | head -1)
  [ -n "$URL" ] && break
  sleep 1
done
if [ -z "$URL" ]; then echo "The tunnel did not start. See logs/tunnel.log"; ./stop.sh >/dev/null; exit 1; fi
nohup python3 sthir_net.py node --port $NP --host 127.0.0.1 --advertise "$URL" $(miner_arg) $(seed_args) --data sthir-data/node1 $RULES > logs/node1.log 2>&1 &
echo $! > logs/node1.pid
start_ui
sleep 2
echo "Your node is public at: $URL"
echo "Another phone joins with:  ./join.sh $URL"
echo "Keep this phone awake and Termux running. The address changes if you restart."
echo "Open in your browser: http://127.0.0.1:$UP"
