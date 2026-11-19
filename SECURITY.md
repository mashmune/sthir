# Security

Sthir is experimental software. Do not protect money you cannot afford to lose with it.

## Reporting a vulnerability

Please report privately: use **Security > Report a vulnerability** on this repository's GitHub page.
Do not open a public issue for a security problem. You will get a reply as soon as a maintainer can read it.

## Known limits (not bugs, but you should know)

- A small network can be overpowered by one person with a rented server (51% attack).
- Wallet keys are protected by your password only. There is no "forgot password". Lose the password and every backup, and the coins are gone.
- The offline voucher lock is held by a hub's own ledger, not by the chain, so offline payments are bounded-risk, not safe.
- The zero-knowledge code is a teaching-level implementation: pure Python, variable-time, not audited.
- Nodes have no passwords. Run `./start.sh share` only on a WiFi you trust.
- The wallet page binds to 127.0.0.1. Do not expose it to the internet.
