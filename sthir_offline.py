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
  * HONEST STATUS: the lock lives inside this hub's own ledger (a JSON file). It is NOT
    yet enforced by the Sthir chain, so the coins are only truly safe once `lock` and
    `redeem` become chain transactions (a consensus upgrade, planned, not done here).

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

from sthir import UNIT, Wallet, verify_sig

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
class HubError(ValueError):
    pass


class Hub:
    """Holds the lock, pays redemptions, detects double use. State lives in a JSON file."""

    def __init__(self, path: str | None = None, wallet: Wallet | None = None, now=time.time):
        self.path, self.now, self.lock = path, now, threading.RLock()
        self.wallet = wallet or Wallet()
        self.s = {"balances": {}, "books": {}, "redeemed": {}, "banned": {}, "burned": 0, "used_nonces": []}
        if path and os.path.exists(path):
            with open(path) as f:
                self.s = json.load(f)

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
        """Fund an account. In a real deployment this mirrors the chain, not a faucet."""
        with self.lock:
            self.s["balances"][addr] = self.balance(addr) + int(amount)
            self._save()

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
                self.s["balances"][to] = self.balance(to) + pay
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
            self.s["balances"][to] = self.balance(to) + pay
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
            self.s["balances"][issuer] = self.balance(issuer) + back
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
            return {"hub": hub.address, "books": len(hub.s["books"]), "banned": len(hub.s["banned"])}
        if path == "/voucher/lock":
            return hub.lock_book(b)
        if path == "/voucher/redeem":
            return hub.redeem(b)
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
        if path == "/admin/credit" and allow_credit:
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
    hub = Hub(os.path.join(a.data, "hub.json"), w)
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
