# Sthir

An experimental proof-of-work coin and wallet that runs on a phone (Termux on Android) or any Linux computer.
Pure Python 3 with one dependency (`cryptography`). **This is a research and learning project, not a financial product.**

> **Disclaimer.** Sthir coins have no price, no promised value and are not an investment. Nobody is selling them.
> The software is provided as is, with no warranty (see LICENSE). Do not use it to protect money you cannot afford to lose.

## What it is today

| Part | What it does | Status |
|---|---|---|
| Chain | Proof-of-work blocks, halving rewards, difficulty retarget, longest-work fork choice, Ed25519 signatures | Works, tested |
| Network | HTTP gossip between nodes, peer exchange, sync, saved chain with full re-validation on start | Works, tested on one machine |
| Wallet page | Profiles with name + password, login/logout, send, receive, ledger, backup text, QR codes (show, save, share, read from gallery), mining on/off | Works in Chromium; QR reading needs Android Chrome |
| Offline vouchers | "Voucher + Cap" state machine for offline payments, with double-spend detection and a bond | Works as a module; **not enforced by the chain yet** |
| Verifiable compute | Merkle-committed step traces, spot checks, and a bisection dispute where a phone referees one step | Works on a toy kernel; **not a zero-knowledge proof** |
| Confidential amounts | Pedersen commitments with range and balance proofs | Works as a module; **unaudited, not wired into the chain** |
| Relay | Store-and-forward mailbox for encrypted blobs | Works |

## What it is not

- It is **not** a live public network. This repository is code. A phone on mobile data has no public address, so nobody can "join Sthir"
  unless someone runs a reachable node and shares its address. Starting a network, and keeping it secure, is separate work.
- It does not replace Bitcoin or any other coin, and it makes no claims about scale, speed or privacy beyond what the tests show.
- It has no Bluetooth or SMS payment. Offline vouchers can be carried by QR code or copied text.
- It is not zero-knowledge for heavy computation. See `docs/ARCHITECTURE.md` for what is real, what is research, and what cannot work.

## Install (Termux or Linux)

```
pkg install -y git python python-cryptography      # on Debian/Ubuntu: sudo apt install git python3 python3-cryptography
git clone https://github.com/mashmune/sthir
cd sthir && ./setup.sh
```

Then open **http://127.0.0.1:8080**, create a profile (name + password) and back it up under More > Account.

| Command | What it does |
|---|---|
| `./start.sh` | run on this phone only (two nodes and the wallet page) |
| `./start.sh share` | also let phones on the same WiFi join; use only on a WiFi you trust |
| `./join.sh http://<ip>:5001` | join another phone's node |
| `./stop.sh` | stop everything |
| `./offline.sh demo` / `verify` / `zk` | run the offline voucher, verification and zero-knowledge demos |
| `python3 -m unittest` | run the test suite |

Your keys and chain live in `accounts.json` and `sthir-data/`. They are ignored by git. **Never commit them.**

## Keys and recovery

A profile is a password-locked key (scrypt + AES-256-GCM). The password never leaves your phone. There is no "forgot password":
if you lose both the password and your backup text, the coins are gone. Back up before you receive anything.

## Layout

```
sthir.py          chain, blocks, wallet, signatures
sthir_net.py      node, gossip, miner, sealed-backup relay
sthir_auth.py     accounts, password vaults, backups
sthir_ui.py       wallet page (served locally)
sthir_offline.py  offline vouchers, relay, small HTTP service
sthir_verify.py   verifiable compute: commit, spot check, dispute
sthir_zk.py       confidential amounts: range and balance proofs
sthir_fastapi.py  optional FastAPI front for the offline service
test_*.py         tests
docs/             architecture, what is real and what is not
```

## Contributing and security

See CONTRIBUTING.md. Report vulnerabilities privately as described in SECURITY.md.

## License

MIT. See LICENSE.
