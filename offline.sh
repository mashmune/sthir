#!/usr/bin/env bash
cd "$(dirname "$0")"
case "$1" in
  demo)   python3 sthir_offline.py demo ;;
  verify) python3 sthir_verify.py ;;
  zk)     python3 sthir_zk.py ;;
  serve)  shift; python3 sthir_offline.py serve "$@" ;;
  *) echo "Usage: ./offline.sh demo | verify | zk | serve [--port 5101] [--node http://127.0.0.1:5000] [--demo-credit]" ;;
esac
