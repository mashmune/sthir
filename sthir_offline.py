"""Sthir offline payments: "Voucher + Cap".

How it works
  1. BEFORE going offline the owner asks a hub to lock coins: `count` vouchers of `value`
     each, plus a bond. The hub signs an attestation of that lock (a stand-in for a chain
     inclusion proof).
  2. OFFLINE, paying means signing one numbered voucher to the receiver. The receiver
     checks it with `Receiver.check` using only the attestation and its own list of
     numbers already seen. No network needed.
  3. ONLINE, receivers redeem. The hub pays each (book, number) once. A second redemption
     of the same number with a different receiver is proof of fraud: the owner is
     banned, the bond is forfeited, and it pays the later receiver first.

What this does and does not give
  * Cap: total payable from one book can never exceed what was locked.
  * Two offline receivers can still BOTH accept the same voucher number. One of them is
    only repaid up to the unspent lock plus the bond. Shops should therefore limit the
    value of each offline sale. The state machine below makes the loss bounded, not zero.
  * CHAIN MODE (`serve --node URL`): the hub is wired to a real Sthir node. Coins are
    deposited by an ordinary on-chain transfer to the hub's address, and every redeem (or
    close, or withdraw) is paid out as an ordinary on-chain transfer. The receiver's wallet
    balance therefore changes on the real chain, after the next block. Without --node the
    hub keeps a private JSON ledger (demo mode) that no wallet can see.
  * HONEST STATUS: the lock is still custodial. The hub's key holds the escrowed coins and
    the chain does not enforce the voucher rules; the hub operator must be trusted. Making
    `lock` and `redeem` consensus rules is a larger upgrade, planned, not done here.

Book states:    LOCKED -> CLOSED (after expiry + grace, remainder returned)
                       -> SLASHED (fraud proven; bond forfeited)
Voucher states: UNUSED -> ACCEPTED (receiver, offline) -> REDEEMED (hub)
                                                       -> REJECTED (duplicate or late)

Also here: a small store-and-forward relay for opaque encrypted blobs, a pluggable
signature scheme (Ed25519 today, ML-DSA if the `oqs` package is installed), and the HTTP
front (`python sthir_offline.py serve`).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import urllib.error

from sthir import UNIT, Tx, Wallet, verify_sig
from sthir_net import http_get, http_post, tx_from_dict, tx_to_dict

MAX_BOOK_COUNT = 1000
MAX_LOCK_SECONDS = 30 * 86400
MIN_LOCK_SECONDS = 60
SETTLE_GRACE = 86400          # receivers may redeem this long after expiry
BOND_PCT = 25                 # extra locked on top of the vouchers, forfeited on fraud


class SchemeUnavailable(ValueError):
    pass


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# -------------------------------------------------------------- signature schemes
def sig_verify(scheme: str, address: str, message: bytes, signature: str) -> bool:
    if scheme == "ed25519":
        return verify_sig(address, message, signature)
    if scheme == "ml-dsa-65":                      # lattice-based, NIST FIPS 204
        try:
            import oqs                             # liboqs-python; not bundled, not in Termux by default
        except ImportError:
            raise SchemeUnavailable("ml-dsa-65 needs the 'oqs' package (liboqs). It is not installed here.")
        try:
            with oqs.Signature("ML-DSA-65") as v:
                return bool(v.verify(message, bytes.fromhex(signature), bytes.fromhex(address)))
        except Exception:
            return False
    raise SchemeUnavailable(f"unknown signature scheme {scheme!r}")


# ----------------------------------------------------------------- owner (signs)
def lock_request(wallet: Wallet, count: int, value: int, expiry: int) -> dict:
    body = {"issuer": wallet.address, "scheme": "ed25519", "count": count, "value": value,
            "expiry": expiry, "nonce": secrets.token_hex(8)}
    return dict(body, sig=wallet.sign(canon(body)))


def withdraw_request(wallet: Wallet, amount: int) -> dict:
    body = {"account": wallet.address, "scheme": "ed25519", "amount": amount, "nonce": secrets.token_hex(8)}
    return dict(body, sig=wallet.sign(canon(body)))


def issue_voucher(wallet: Wallet, book: dict, n: int, to: str, ts: int | None = None) -> dict:
    body = {"book": book["id"], "n": n, "to": to, "value": book["value"], "ts": int(ts or time.time())}
    return dict(body, sig=wallet.sign(canon(body)))


def _voucher_body(v: dict) -> dict:
    return {k: v[k] for k in ("book", "n", "to", "value", "ts")}


# ----------------------------------------------------------------------- receiver
class Receiver:
    """The offline side: a shop or a person who accepts vouchers with no network."""

    def __init__(self, address: str, hub_address: str, per_sale_cap: int, now=time.time):
        self.address, self.hub, self.cap, self.now = address, hub_address, per_sale_cap, now
        self.seen: set[tuple[str, int]] = set()
        self.accepted: list[dict] = []

    def check(self, voucher: dict, attested: dict) -> tuple[bool, str]:
        try:
            book = attested["book"]
            if not sig_verify("ed25519", self.hub, canon(book), attested["hub_sig"]):
                return False, "the lock attestation is not signed by the hub you trust"
            if voucher["book"] != book["id"] or voucher["to"] != self.address:
                return False, "voucher is for a different book or a different receiver"
            if not (isinstance(voucher["n"], int) and 0 <= voucher["n"] < book["count"]):
                return False, "voucher number is outside the book"
            if voucher["value"] != book["value"]:
                return False, "voucher value does not match the book"
            if voucher["value"] > self.cap:
                return False, "this sale is above your offline limit"
            if self.now() > book["expiry"]:
                return False, "this book has expired"
            if not sig_verify(book["scheme"], book["issuer"], canon(_voucher_body(voucher)), voucher["sig"]):
                return False, "signature is not from the book's owner"
            if (voucher["book"], voucher["n"]) in self.seen:
                return False, "you already accepted this voucher number"
        except (KeyError, TypeError, SchemeUnavailable) as e:
            return False, f"malformed or unsupported voucher ({type(e).__name__})"
        return True, "ok"

    def accept(self, voucher: dict, attested: dict) -> tuple[bool, str]:
        ok, why = self.check(voucher, attested)
        if ok:
            self.seen.add((voucher["book"], voucher["n"]))
            self.accepted.append(voucher)
        return ok, why


# -------------------------------------------------------------------------- hub
class ChainError(Exception):
    pass


class ChainBridge:
    """Talks to a Sthir node over HTTP: reads deposits, sends payouts."""
    FEE = UNIT // 100            # paid to the miner on each payout, taken out of that payout

    def __init__(self, node_url: str, confirmations: int = 2, get=None, post=None):
        self.url, self.confirmations = node_url.rstrip("/"), max(1, int(confirmations))
        self._get, self._post = get or http_get, post or http_post

    def _call(self, fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except urllib.error.HTTPError as e:
            raise ChainError(e.read().decode(errors="replace")[:200])
        except (OSError, ValueError) as e:
            raise ChainError(f"node unreachable ({type(e).__name__})")

    def tip(self) -> int:
        return int(self._call(self._get, self.url + "/status")["height"])

    def blocks(self) -> list:
        return self._call(self._get, self.url + "/chain", timeout=30)

    def account(self, addr: str) -> dict:
        return self._call(self._get, f"{self.url}/account/{addr}")

    def submit(self, tx: Tx) -> dict:
        return self._call(self._post, self.url + "/tx", tx_to_dict(tx))


class HubError(ValueError):
    pass


class Hub:
    """Holds the lock, pays redemptions, detects double use. State lives in a JSON file."""

    def __init__(self, path: str | None = None, wallet: Wallet | None = None, now=time.time,
                 chain: "ChainBridge | None" = None):
        self.path, self.now, self.lock = path, now, threading.RLock()
        self.wallet, self.chain = wallet or Wallet(), chain
        self.s = {"balances": {}, "books": {}, "redeemed": {}, "banned": {}, "burned": 0, "used_nonces": []}
        if path and os.path.exists(path):
            with open(path) as f:
                self.s = json.load(f)
        # chain-mode state; older files simply gain these keys
        for k, v in (("deposits", {}), ("scanned", 0), ("payouts", {}), ("inflight", None), ("sent", [])):
            self.s.setdefault(k, v)

    @property
    def address(self) -> str:
        return self.wallet.address

    def _save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.s, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def balance(self, addr: str) -> int:
        return self.s["balances"].get(addr, 0)

    def credit(self, addr: str, amount: int):
        """Test faucet for demo mode. With a chain attached, funds only arrive as deposits."""
        if self.chain:
            raise HubError("this hub is connected to a chain: send coins to it on-chain instead")
        with self.lock:
            self.s["balances"][addr] = self.balance(addr) + int(amount)
            self._save()

    def _settle(self, addr: str, amount: int):
        """Pay `amount` to `addr`: on-chain (queued) in chain mode, else the private ledger.
        Caller holds the lock and saves."""
        if amount <= 0:
            return
        book = self.s["payouts"] if self.chain else self.s["balances"]
        book[addr] = book.get(addr, 0) + amount

    def pending_payout(self, addr: str) -> int:
        inf = self.s["inflight"]
        return self.s["payouts"].get(addr, 0) + (inf["amount"] + inf["fee"] if inf and inf["to"] == addr else 0)

    # ---- chain mode: deposits in, payouts out
    def sync_deposits(self) -> int:
        """Credit on-chain transfers to the hub address once they are `confirmations` deep."""
        if not self.chain:
            return 0
        with self.lock:
            try:
                limit = self.chain.tip() - self.chain.confirmations + 1
                blocks = self.chain.blocks()
            except (ChainError, KeyError, TypeError):
                return 0
            n, top = 0, self.s["scanned"]
            for b in blocks:
                h = b.get("height", 0)
                if h <= self.s["scanned"] or h > limit:
                    continue
                top = max(top, h)
                for td in b.get("txs", []):
                    try:
                        tx = tx_from_dict(td)
                    except (KeyError, ValueError, TypeError):
                        continue
                    if tx.recipient != self.address or tx.sender == self.address:
                        continue
                    if not verify_sig(tx.sender, tx.body(), tx.signature):
                        continue
                    tid = tx.txid()
                    if tid in self.s["deposits"]:
                        continue
                    self.s["deposits"][tid] = h
                    self.s["balances"][tx.sender] = self.balance(tx.sender) + tx.amount
                    n += 1
            self.s["scanned"] = top
            self._save()
            return n

    def flush_payouts(self) -> int:
        """Send queued payouts as real transactions, one at a time. Returns how many went out.
        An intent is saved before each send, so a crash can never pay the same amount twice."""
        if not self.chain:
            return 0
        sent, fee = 0, self.chain.FEE
        with self.lock:
            while True:
                inf = self.s["inflight"]
                if inf is None:
                    todo = [(a, m) for a, m in self.s["payouts"].items() if m > fee]
                    if not todo:
                        break
                    addr, gross = todo[0]
                    try:
                        nonce = self.chain.account(self.address)["next_nonce"]
                    except (ChainError, KeyError):
                        break
                    inf = {"to": addr, "amount": gross - fee, "fee": fee, "nonce": nonce}
                    del self.s["payouts"][addr]
                    self.s["inflight"] = inf
                    self._save()
                tx = Tx.create(self.wallet, inf["to"], inf["amount"], inf["fee"], inf["nonce"])
                try:
                    self.chain.submit(tx)
                    ok = True
                except ChainError:
                    try:        # a timeout may hide a success: our nonce moved on, so it went in
                        ok = self.chain.account(self.address)["next_nonce"] > inf["nonce"]
                    except (ChainError, KeyError):
                        ok = False
                if not ok:
                    break
                self.s["sent"] = (self.s["sent"] + [{"to": inf["to"], "amount": inf["amount"],
                                                      "txid": tx.txid(), "at": int(self.now())}])[-200:]
                self.s["inflight"] = None
                self._save()
                sent += 1
        return sent

    def withdraw(self, req: dict) -> dict:
        """Move an account's deposited (unlocked) balance back to its own on-chain address."""
        if not self.chain:
            raise HubError("this hub has no chain connection")
        with self.lock:
            try:
                body = {k: req[k] for k in ("account", "scheme", "amount", "nonce")}
                ok = sig_verify(body["scheme"], body["account"], canon(body), req["sig"])
            except (KeyError, TypeError, SchemeUnavailable) as e:
                raise HubError(f"malformed withdraw request ({type(e).__name__})")
            amt = body["amount"]
            if not ok:
                raise HubError("withdraw request is not signed by the account")
            if not isinstance(amt, int) or amt <= self.chain.FEE:
                raise HubError("amount must be more than the network fee")
            if body["nonce"] in self.s["used_nonces"]:
                raise HubError("this request was already used")
            if self.balance(body["account"]) < amt:
                raise HubError("not enough unlocked coins at the hub")
            self.s["balances"][body["account"]] -= amt
            self.s["used_nonces"].append(body["nonce"])
            self._settle(body["account"], amt)
            self._save()
        sent = self.flush_payouts()
        return {"queued": amt, "sent_now": sent}

    # ---- lock
    def lock_book(self, req: dict) -> dict:
        with self.lock:
            try:
                body = {k: req[k] for k in ("issuer", "scheme", "count", "value", "expiry", "nonce")}
                count, value, expiry = body["count"], body["value"], body["expiry"]
                ok = sig_verify(body["scheme"], body["issuer"], canon(body), req["sig"])
            except (KeyError, TypeError, SchemeUnavailable) as e:
                raise HubError(f"malformed lock request ({type(e).__name__})")
            if not ok:
                raise HubError("lock request is not signed by the issuer")
            if not (isinstance(count, int) and isinstance(value, int) and isinstance(expiry, int)
                    and 1 <= count <= MAX_BOOK_COUNT and value > 0):
                raise HubError("bad count or value")
            t = self.now()
            if not t + MIN_LOCK_SECONDS <= expiry <= t + MAX_LOCK_SECONDS:
                raise HubError("expiry must be between 1 minute and 30 days from now")
            if body["issuer"] in self.s["banned"]:
                raise HubError("this account is banned for earlier fraud")
            if body["nonce"] in self.s["used_nonces"]:
                raise HubError("this request was already used")
            total = count * value
            bond = total * BOND_PCT // 100
            if self.balance(body["issuer"]) < total + bond:
                raise HubError(f"not enough coins: need {(total + bond) / UNIT:g} (vouchers plus a {BOND_PCT}% bond)")
            self.s["balances"][body["issuer"]] -= total + bond
            self.s["used_nonces"].append(body["nonce"])
            book = {"id": hashlib.sha256(canon(body)).hexdigest()[:24], "issuer": body["issuer"],
                    "scheme": body["scheme"], "count": count, "value": value, "expiry": expiry,
                    "bond_pct": BOND_PCT}
            self.s["books"][book["id"]] = {"book": book, "remaining": total, "bond": bond,
                                           "state": "LOCKED", "shortfall": 0}
            self._save()
            return {"book": book, "hub_sig": self.wallet.sign(canon(book))}

    # ---- redeem
    def redeem(self, v: dict) -> dict:
        with self.lock:
            try:
                rec = self.s["books"][v["book"]]
                book = rec["book"]
                n, to = v["n"], v["to"]
                if not (isinstance(n, int) and 0 <= n < book["count"]) or v["value"] != book["value"]:
                    raise HubError("voucher does not match its book")
                if not sig_verify(book["scheme"], book["issuer"], canon(_voucher_body(v)), v["sig"]):
                    raise HubError("signature is not from the book's owner")
            except KeyError:
                raise HubError("unknown book or malformed voucher")
            except SchemeUnavailable as e:
                raise HubError(str(e))
            if rec["state"] == "CLOSED" or self.now() > book["expiry"] + SETTLE_GRACE:
                return {"status": "rejected", "reason": "settlement window is closed"}
            key = f"{book['id']}:{n}"
            first = self.s["redeemed"].get(key)
            if first is None:
                pay = min(book["value"], rec["remaining"])      # less only if earlier fraud drained the lock
                self.s["redeemed"][key] = {"to": to, "voucher": v}
                self._settle(to, pay)
                rec["remaining"] -= pay
                rec["shortfall"] += book["value"] - pay
                self._save()
                return {"status": "paid", "amount": pay, "shortfall": book["value"] - pay}
            if first["to"] == to:
                return {"status": "already_redeemed", "amount": 0}
            # Same number, two receivers: fraud. Pay the later receiver from the bond, then the unspent lock.
            pool = rec["bond"] + rec["remaining"]
            pay = min(book["value"], pool)
            from_bond = min(pay, rec["bond"])
            rec["bond"] -= from_bond
            rec["remaining"] -= pay - from_bond
            rec["shortfall"] += book["value"] - pay
            rec["state"] = "SLASHED"
            self._settle(to, pay)
            self.s["banned"][book["issuer"]] = {"book": book["id"], "n": n, "at": int(self.now()),
                                                "evidence": [first["voucher"], v]}
            self._save()
            return {"status": "fraud_detected", "paid": pay, "shortfall": book["value"] - pay,
                    "issuer_banned": True}

    # ---- status: how a sender (or receiver) finds out whether a voucher was paid
    def voucher_status(self, book_id: str, n: int, to: str | None = None) -> dict:
        """UNUSED, PAID or REJECTED_DUPLICATE. The receiver's address is only confirmed
        (never listed): pass `to` and read `paid_to_you`."""
        with self.lock:
            rec = self.s["books"].get(book_id)
            if rec is None:
                raise HubError("unknown book")
            if not (isinstance(n, int) and 0 <= n < rec["book"]["count"]):
                raise HubError("number is outside the book")
            first = self.s["redeemed"].get(f"{book_id}:{n}")
            out = {"state": "UNUSED" if first is None else "PAID", "book_state": rec["state"],
                   "settlement_open_until": rec["book"]["expiry"] + SETTLE_GRACE}
            if first is not None and to is not None:
                out["paid_to_you"] = first["to"] == to
                if self.chain and first["to"] == to:
                    queued = self.pending_payout(to) > 0
                    out["onchain"] = "queued" if queued else "sent"
            return out

    # ---- close
    def close(self, book_id: str) -> dict:
        with self.lock:
            rec = self.s["books"].get(book_id)
            if rec is None:
                raise HubError("unknown book")
            if rec["state"] == "CLOSED":
                return {"returned": 0}
            if self.now() <= rec["book"]["expiry"] + SETTLE_GRACE:
                raise HubError("the settlement window is still open")
            back = rec["remaining"] + (rec["bond"] if rec["state"] != "SLASHED" else 0)
            if rec["state"] == "SLASHED":
                self.s["burned"] += rec["bond"]
            issuer = rec["book"]["issuer"]
            self._settle(issuer, back)
            rec["remaining"] = rec["bond"] = 0
            if rec["state"] != "SLASHED":
                rec["state"] = "CLOSED"
            else:
                rec["state"] = "CLOSED_SLASHED"
            self._save()
            return {"returned": back}


# ------------------------------------------------------------------------ relay
class Relay:
    """Store-and-forward mailbox for opaque encrypted blobs. The relay never sees plaintext.
    A mailbox id is sha256(token); reading needs the token, so ids alone cannot be read."""
    MAX_BLOB, MAX_PER_BOX, MAX_BOXES, MAX_TTL = 64 * 1024, 100, 5000, 7 * 86400

    def __init__(self, now=time.time):
        self.now, self.boxes, self.lock = now, {}, threading.Lock()

    def put(self, box_id: str, blob_b64: str, ttl: int = 86400) -> dict:
        try:
            raw = base64.b64decode(blob_b64, validate=True)
        except Exception:
            raise HubError("blob must be base64")
        if not (isinstance(box_id, str) and len(box_id) == 64 and all(c in "0123456789abcdef" for c in box_id)):
            raise HubError("box id must be 64 hex characters")
        if len(raw) > self.MAX_BLOB:
            raise HubError("blob is too large")
        ttl = max(60, min(int(ttl), self.MAX_TTL))
        with self.lock:
            self._expire()
            if box_id not in self.boxes and len(self.boxes) >= self.MAX_BOXES:
                raise HubError("relay is full")
            box = self.boxes.setdefault(box_id, [])
            if len(box) >= self.MAX_PER_BOX:
                raise HubError("mailbox is full")
            box.append({"id": secrets.token_hex(6), "blob": blob_b64, "until": self.now() + ttl})
            return {"stored": box[-1]["id"]}

    def get(self, token: str, ack: list | None = None) -> dict:
        box_id = hashlib.sha256(str(token).encode()).hexdigest()
        with self.lock:
            self._expire()
            box = self.boxes.get(box_id, [])
            if ack:
                box[:] = [m for m in box if m["id"] not in set(ack)]
            if not box:
                self.boxes.pop(box_id, None)
            return {"messages": [{"id": m["id"], "blob": m["blob"]} for m in box]}

    def _expire(self):
        t = self.now()
        for k in list(self.boxes):
            self.boxes[k] = [m for m in self.boxes[k] if m["until"] > t]
            if not self.boxes[k]:
                del self.boxes[k]


# --------------------------------------------------------------------- the router
def make_router(hub: Hub, relay: Relay, allow_credit: bool = False):
    from sthir_verify import verify_samples

    def need(b, *keys):
        for k in keys:
            if k not in b:
                raise HubError(f"missing field: {k}")

    def route(path: str, b: dict) -> dict:
        if path == "/status":
            return {"hub": hub.address, "books": len(hub.s["books"]), "banned": len(hub.s["banned"]),
                    "chain": bool(hub.chain), "confirmations": hub.chain.confirmations if hub.chain else None,
                    "network_fee": hub.chain.FEE if hub.chain else 0}
        if path == "/voucher/lock":
            hub.sync_deposits()
            return hub.lock_book(b)
        if path == "/voucher/redeem":
            r = hub.redeem(b)
            hub.flush_payouts()
            return r
        if path == "/voucher/close":
            need(b, "book")
            r = hub.close(b["book"])
            hub.flush_payouts()
            return r
        if path == "/hub/balance":
            need(b, "address")
            hub.sync_deposits()
            return {"unlocked": hub.balance(b["address"]), "pending_payout": hub.pending_payout(b["address"]),
                    "chain": bool(hub.chain)}
        if path == "/hub/withdraw":
            return hub.withdraw(b)
        if path == "/hub/sync":
            return {"deposits": hub.sync_deposits(), "payouts_sent": hub.flush_payouts()}
        if path == "/voucher/status":
            need(b, "book", "n")
            return hub.voucher_status(b["book"], b["n"], b.get("to"))
        if path == "/voucher/check":
            need(b, "voucher", "attested", "receiver", "cap")
            r = Receiver(b["receiver"], hub.address, int(b["cap"]))
            ok, why = r.check(b["voucher"], b["attested"])
            return {"ok": ok, "reason": why}
        if path == "/verify/samples":
            need(b, "claim", "openings")
            return verify_samples(b["claim"], b["openings"], int(b.get("k", 16)))
        if path == "/relay/put":
            need(b, "box", "blob")
            return relay.put(b["box"], b["blob"], b.get("ttl", 86400))
        if path == "/relay/get":
            need(b, "token")
            return relay.get(b["token"], b.get("ack"))
        if path == "/admin/credit" and allow_credit and not hub.chain:
            need(b, "address", "amount")
            hub.credit(b["address"], int(b["amount"]))
            return {"balance": hub.balance(b["address"])}
        raise KeyError(path)
    return route


def make_handler(route, limit=262144):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path.rstrip("/") == "/status":
                return self._send(200, route("/status", {}))
            self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n > limit:
                    return self._send(413, {"error": "too large"})
                if "application/json" not in self.headers.get("Content-Type", ""):
                    return self._send(415, {"error": "send application/json"})
                body = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(body, dict):
                    raise HubError("body must be a JSON object")
                self._send(200, route(self.path.rstrip("/"), body))
            except KeyError:
                self._send(404, {"error": "not found"})
            except (HubError, ValueError, TypeError, AttributeError, IndexError) as e:
                self._send(400, {"error": str(e) or "bad request"})
            except Exception:
                self._send(500, {"error": "server error"})
    return H


# ------------------------------------------------------------------------- demo
def _coins(x):
    return f"{x / UNIT:g}"


def demo() -> None:
    t = [1_800_000_000.0]
    hub = Hub(now=lambda: t[0])
    asha, ravi, meena = Wallet(), Wallet(), Wallet()
    hub.credit(asha.address, 1000 * UNIT)
    print(f"Asha has {_coins(hub.balance(asha.address))} coins.")

    att = hub.lock_book(lock_request(asha, count=25, value=20 * UNIT, expiry=int(t[0]) + 7 * 86400))
    book = att["book"]
    print(f"\n1. ONLINE: Asha locks a book of 25 vouchers x 20 coins (500) plus a 25% bond (125).")
    print(f"   Asha's free balance is now {_coins(hub.balance(asha.address))}.")

    ravi_shop = Receiver(ravi.address, hub.address, per_sale_cap=50 * UNIT, now=lambda: t[0])
    meena_shop = Receiver(meena.address, hub.address, per_sale_cap=50 * UNIT, now=lambda: t[0])
    v_ravi = issue_voucher(asha, book, 7, ravi.address, t[0])
    v_meena = issue_voucher(asha, book, 7, meena.address, t[0])      # SAME number to someone else
    print("\n2. OFFLINE (no internet): Asha pays Ravi with voucher #7, then cheats: the same #7 to Meena.")
    print("   Ravi  accepts:", ravi_shop.accept(v_ravi, att))
    print("   Meena accepts:", meena_shop.accept(v_meena, att), " <- she cannot know; she is offline too")
    print("   Ravi, offered #7 again:", ravi_shop.accept(v_ravi, att))
    big = Receiver(ravi.address, hub.address, per_sale_cap=10 * UNIT, now=lambda: t[0])
    print("   A shop with a 10-coin limit refuses the 20-coin voucher:", big.accept(issue_voucher(asha, book, 8, ravi.address, t[0]), att))

    print("\n3. ONLINE: both settle.")
    print("   Ravi  redeems:", hub.redeem(v_ravi))
    r = hub.redeem(v_meena)
    print("   Meena redeems:", r)
    print("   Sender checks voucher #7 status for Ravi:", hub.voucher_status(book["id"], 7, ravi.address))
    print("   Voucher #8 (never spent):", hub.voucher_status(book["id"], 8)["state"])
    print(f"   Ravi has {_coins(hub.balance(ravi.address))}, Meena has {_coins(hub.balance(meena.address))}. "
          f"Asha is banned: {asha.address in hub.s['banned']}.")
    try:
        hub.lock_book(lock_request(asha, 1, UNIT, int(t[0]) + 3600))
    except HubError as e:
        print("   Asha tries a new book:", e)

    t[0] += 7 * 86400 + SETTLE_GRACE + 1
    print("\n4. After expiry plus grace:", hub.close(book["id"]), "(unspent lock returned; the bond was forfeited)")
    print("   late redeem:", hub.redeem(issue_voucher(asha, book, 9, ravi.address, t[0])))
    print("\nBounded loss: a receiver is repaid from the bond plus unspent lock. If many numbers are")
    print("double-spent at once the pool runs out and the shortfall is the receiver's loss.")


def main():
    ap = argparse.ArgumentParser(prog="sthir_offline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="walk through a double-spend attempt")
    s = sub.add_parser("serve", help="run the voucher, verify and relay HTTP service")
    s.add_argument("--port", type=int, default=5101)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--data", default="sthir-offline")
    s.add_argument("--demo-credit", action="store_true", help="enable /admin/credit (test coins). Never on a public host.")
    s.add_argument("--node", default=None, help="Sthir node URL, e.g. http://127.0.0.1:5000. Turns on chain mode: real deposits and payouts.")
    s.add_argument("--confirmations", type=int, default=2, help="blocks a deposit must be buried under (chain mode)")
    a = ap.parse_args()
    if a.cmd == "demo":
        return demo()
    os.makedirs(a.data, exist_ok=True)
    keyf = os.path.join(a.data, "hub.key")
    if os.path.exists(keyf):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        w = Wallet(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(keyf).read().strip())))
    else:
        w = Wallet()
        from cryptography.hazmat.primitives import serialization
        raw = w._sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption()).hex()
        fd = os.open(keyf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(raw)
    bridge = ChainBridge(a.node, a.confirmations) if a.node else None
    hub = Hub(os.path.join(a.data, "hub.json"), w, chain=bridge)
    if bridge:
        def _loop():
            while True:
                try:
                    hub.sync_deposits()
                    hub.flush_payouts()
                except Exception:
                    pass
                time.sleep(20)
        threading.Thread(target=_loop, daemon=True).start()
        print(f"Chain mode: deposits and payouts go through {bridge.url}. Send coins to the hub address to fund an account.")
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(make_router(hub, Relay(), a.demo_credit)))
    srv.daemon_threads = True
    print(f"Sthir offline hub {hub.address[:12]}... on http://{a.host}:{a.port}")
    if a.host != "127.0.0.1":
        print("WARNING: reachable from the network. Use it only on a network you trust.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
