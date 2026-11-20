# Shared helpers for start.sh and join.sh
NP=${STHIR_PORT:-5001}       # node port
UP=${STHIR_UI_PORT:-8080}    # wallet page port

lan_ip() {
  python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(('10.255.255.255',1));print(s.getsockname()[0])" 2>/dev/null || echo 127.0.0.1
}
begin() {
  ./stop.sh >/dev/null 2>&1
  mkdir -p logs
  command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock
}
# Where mining rewards go: the profile last logged in, else an old key file, else wait for a login.
miner_arg() {
  if [ -f miner.addr ]; then echo "--mine $(cat miner.addr)"
  elif [ -f wallet.key ]; then echo "--mine wallet.key"
  else echo "--mine-later"; fi
}
start_ui() {
  nohup python3 sthir_ui.py --node http://127.0.0.1:$NP --key wallet.key --port $UP > logs/ui.log 2>&1 &
  echo $! > logs/ui.pid
}
# Public seed nodes everyone connects to. One URL per line in seeds.txt (lines starting with # are ignored).
seed_args() {
  [ -f seeds.txt ] || return 0
  grep -v '^[[:space:]]*#' seeds.txt | grep -E '^https?://' | sed 's/^/--peer /' | tr '\n' ' '
}
