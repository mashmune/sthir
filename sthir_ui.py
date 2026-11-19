"""Sthir wallet UI v0.4

A small web wallet that runs on your own device and talks to a Sthir node.
Open http://127.0.0.1:8080 in the phone's browser after starting it.

  python sthir_ui.py --node http://127.0.0.1:5001 --key wallet.key

Accounts: each profile has a name and a password. The key is sealed with the
password (see sthir_auth.py); logging in unseals it in memory, logging out or
leaving the wallet idle forgets it again. The page only listens on 127.0.0.1
and rejects requests that did not come from its own page.
Needs sthir.py, sthir_net.py and sthir_auth.py in the same folder.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from sthir import UNIT, Tx
from sthir_auth import (
    AccountStore, BadPassword, Locked, Throttle, check_password_rules, legacy_keys,
    make_export, migrate_legacy, new_key_hex, open_vault, parse_export, relay_id,
    seal, validate_name, wallet_from_hex,
)
from sthir_net import block_from_dict, http_get, http_post, tx_to_dict

FRIENDLY = {
    "insufficient balance": "Not enough coins to cover the amount and the fee.",
    "bad nonce": "Another payment is still being processed. Try again in a moment.",
    "bad signature": "The payment could not be signed. Check the key file.",
}
IDLE_SECONDS = 15 * 60
COOKIE = "sthir_session"
PUBLIC = {"/api/auth/signup", "/api/auth/login", "/api/auth/import",
          "/api/auth/remote", "/api/auth/logout"}


def parse_units(text: str, allow_zero: bool = False) -> int:
    try:
        d = Decimal(str(text).strip())
    except InvalidOperation:
        raise ValueError("Enter the amount as a number, for example 2.5.")
    scaled = d * UNIT
    if not d.is_finite() or scaled != scaled.to_integral_value():
        raise ValueError("Use at most 8 decimal places.")
    if d < 0 or (d == 0 and not allow_zero):
        raise ValueError("Enter an amount greater than 0.")
    return int(scaled)


def relay_request(relay: str, rid: str, blob: str | None = None):
    """Talk to the vault relay of a node. GET when blob is None, otherwise store it."""
    base = str(relay or "").strip().rstrip("/")
    if not re.fullmatch(r"https?://[^\s/]+(:\d+)?", base):
        raise ValueError("The relay address should look like http://192.168.1.5:5001")
    url = f"{base}/vault/{rid}"
    try:
        if blob is None:
            with urllib.request.urlopen(url, timeout=8) as r:
                return json.loads(r.read(9000))["blob"]
        req = urllib.request.Request(url, json.dumps({"blob": blob}).encode(),
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            r.read(1000)
        return None
    except urllib.error.HTTPError as e:
        if e.code == 404 and blob is None:
            raise ValueError("No backup found for this name and password on that relay.")
        if e.code == 429:
            raise ValueError("The relay is busy. Wait a minute and try again.")
        raise ValueError("The relay refused the request.")
    except (OSError, ValueError, KeyError):
        raise ValueError("Can't reach the relay. Check the address and that it is running.")


class UIState:
    def __init__(self, node_url: str, key_path: str):
        self.node = node_url.rstrip("/")
        self.key_path = key_path  # the old plaintext key file, only read for migration
        self.key_abs = os.path.abspath(key_path)
        self.dir = os.path.dirname(self.key_abs)
        self.backup_dir = os.path.join(self.dir, "wallet-backups")
        self.store = AccountStore(os.path.join(self.dir, "accounts.json"))
        self.throttle = Throttle()
        self.lock = threading.Lock()    # guards the fields below
        self.wlock = threading.Lock()   # one account operation at a time
        self.sess: dict | None = None   # {token, id, name, wallet, last}
        self.pending: dict[str, dict] = {}
        self.cache_tip = None
        self.blocks: list[dict] = []
        self.ledger: list[dict] = []

    # ------------------------------------------------------------- session
    def _alive(self) -> bool:
        s = self.sess
        if s and time.time() - s["last"] > IDLE_SECONDS:
            self.sess = None
            self.pending.clear()
            self.cache_tip, self.blocks, self.ledger = None, [], []
        return self.sess is not None

    def authed(self, token) -> bool:
        with self.lock:
            return bool(token) and self._alive() and hmac.compare_digest(
                str(token), self.sess["token"])

    def touch(self) -> None:
        with self.lock:
            if self._alive():
                self.sess["last"] = time.time()

    def _login(self, acct: dict, key_hex: str) -> dict:
        wallet = wallet_from_hex(key_hex)
        with self.lock:
            token = secrets.token_hex(24)
            self.sess = {"token": token, "id": acct["id"], "name": acct["name"],
                         "wallet": wallet, "last": time.time()}
            self.pending.clear()
            self.cache_tip, self.blocks, self.ledger = None, [], []
        self._follow_miner(wallet.address)
        return {"_token": token, "name": acct["name"], "address": wallet.address}

    def logout(self) -> dict:
        with self.lock:
            self.sess = None
            self.pending.clear()
            self.cache_tip, self.blocks, self.ledger = None, [], []
        return {"_clear": True}

    def _current(self) -> dict:
        with self.lock:
            if not self._alive():
                raise PermissionError("locked")
            return self.sess

    def _verify(self, password: str) -> tuple[dict, str]:
        """Check the password of the logged-in account again (for sensitive actions)."""
        s = self._current()
        acct = self.store.get(s["id"])
        self.throttle.check(acct["id"])
        try:
            key = open_vault(acct["vault"], str(password or ""))
        except BadPassword:
            self.throttle.fail(acct["id"])
            raise
        self.throttle.ok(acct["id"])
        return acct, key

    # --------------------------------------------------------------- mining
    def _follow_miner(self, address: str) -> bool:
        """Make this device's node pay mining rewards to the logged-in account, but only
        if the node was mining for one of this phone's own accounts (or not yet set)."""
        try:
            tmp = os.path.join(self.dir, "miner.addr.tmp")
            with open(tmp, "w") as f:
                f.write(address)
            os.replace(tmp, os.path.join(self.dir, "miner.addr"))
        except OSError:
            pass
        try:
            current = http_get(self.node + "/status", timeout=4).get("miner")
            mine = self.store.addresses() | {w for _, w in self._legacy_addresses()}
            if current == address or (current is not None and current not in mine):
                return current == address
            req = urllib.request.Request(
                self.node + "/miner", json.dumps({"address": address}).encode(),
                {"Content-Type": "application/json", "X-Sthir-UI": "1"})
            with urllib.request.urlopen(req, timeout=4) as r:
                return json.loads(r.read()).get("miner") == address
        except Exception:
            return False

    def set_mining(self, on: bool) -> dict:
        """Switch this phone's node on or off. Turning on also points rewards at the
        logged-in account, so the coins land in the wallet that is open."""
        if not self.sess:
            raise PermissionError("logged out")
        me = self.sess["wallet"].address
        if on and not self._follow_miner(me):
            raise ValueError("This node is already mining for a different wallet, so it was not changed.")
        req = urllib.request.Request(
            self.node + "/mining", json.dumps({"on": bool(on)}).encode(),
            {"Content-Type": "application/json", "X-Sthir-UI": "1"})
        try:
            with urllib.request.urlopen(req, timeout=4) as r:
                return {"mining": json.loads(r.read()).get("mining")}
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error")
            except Exception:
                msg = None
            raise ValueError(msg or "The node refused. Restart it with start.sh so it can mine.")
        except Exception:
            raise ValueError("Can't reach the node.")

    def _legacy_addresses(self):
        return [(p, wallet_from_hex(k).address) for k, p in legacy_keys(self.key_abs, self.backup_dir)]

    # ---------------------------------------------------------------- state
    def _refresh_chain(self, me: str):
        chain = http_get(self.node + "/chain", timeout=30)
        ledger = []
        for d in chain:
            fees = 0
            for t in d["txs"]:
                fees += int(t["fee"])
                if t["sender"] == me or t["recipient"] == me:
                    sent = t["sender"] == me
                    ledger.append({
                        "kind": "sent" if sent else "received",
                        "height": d["height"], "ts": d["timestamp"],
                        "amount": int(t["amount"]),
                        "fee": int(t["fee"]) if sent else 0,
                        "peer": t["recipient"] if sent else t["sender"],
                    })
            if d["miner"] == me:
                ledger.append({"kind": "mined", "height": d["height"],
                               "ts": d["timestamp"],
                               "amount": int(d["reward"]) + fees,
                               "fee": 0, "peer": ""})
        ledger.reverse()
        self.ledger = ledger[:100]
        recent = []
        for d in reversed(chain[-12:]):
            b = block_from_dict(d)
            recent.append({"height": b.height, "hash": b.hash(), "ts": b.timestamp,
                           "miner": b.miner, "txs": len(b.txs), "mine": b.miner == me})
        self.blocks = recent

    def locked_state(self) -> dict:
        return {"locked": True, "accounts": self.store.listing(), "node": self.node,
                "legacy": bool(legacy_keys(self.key_abs, self.backup_dir))}

    def state(self, token) -> dict:
        if not self.authed(token):
            return self.locked_state()
        with self.lock:
            s = self.sess
            wallet, name, acct_id = s["wallet"], s["name"], s["id"]
        me = wallet.address
        out = {"locked": False, "address": me, "node": self.node, "node_ok": False,
               "account": {"id": acct_id, "name": name}, "idle": IDLE_SECONDS}
        try:
            st = http_get(self.node + "/status", timeout=4)
            acct = http_get(f"{self.node}/account/{me}", timeout=4)
            peers = http_get(self.node + "/peers", timeout=4)["peers"]
            with self.lock:
                if not self.sess or self.sess["wallet"].address != me:
                    raise RuntimeError("logged out")
                if st["tip"] != self.cache_tip:
                    self._refresh_chain(me)
                    self.cache_tip = st["tip"]
                self.pending = {k: v for k, v in self.pending.items()
                                if v["nonce"] >= acct["nonce"]}
                pend = sorted(self.pending.values(), key=lambda p: -p["ts"])
                reserved = sum(p["amount"] + p["fee"] for p in pend)
                out.update(
                    node_ok=True, status=st, balance=acct["balance"],
                    available=max(acct["balance"] - reserved, 0),
                    pending=pend, peers=peers, blocks=self.blocks,
                    ledger=self.ledger, mining=st.get("miner") == me,
                    mining_on=bool(st.get("mining")) and st.get("miner") == me)
        except Exception as e:
            out["error"] = str(e)
        return out

    def send(self, to: str, amount_text: str, fee_text: str) -> dict:
        wallet = self._current()["wallet"]
        to = str(to).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", to):
            raise ValueError("Address must be 64 characters using 0-9 and a-f.")
        amount = parse_units(amount_text)
        fee = parse_units(fee_text, allow_zero=True)
        try:
            acct = http_get(f"{self.node}/account/{wallet.address}", timeout=5)
        except Exception:
            raise ValueError("Can't reach the node. Check that it is running.")
        tx = Tx.create(wallet, to, amount, fee, acct["next_nonce"])
        try:
            res = http_post(self.node + "/tx", tx_to_dict(tx))
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read())["error"].split(": ", 1)[-1]
            except Exception:
                msg = "rejected"
            raise ValueError(FRIENDLY.get(msg, f"The node rejected the payment: {msg}"))
        except Exception:
            raise ValueError("Can't reach the node. Check that it is running.")
        txid = tx.txid()
        with self.lock:
            self.pending[txid] = {"txid": txid, "to": to, "amount": amount,
                                  "fee": fee, "nonce": tx.nonce, "ts": int(time.time())}
        return {"txid": txid, "result": res.get("result")}

    # ------------------------------------------------------------- accounts
    def signup(self, name, password, use_existing=False) -> dict:
        name = validate_name(name)
        check_password_rules(password)
        with self.wlock:
            if self.store.by_name(name):
                raise ValueError("A profile with this name already exists. Log in instead.")
            migrated = 0
            items = legacy_keys(self.key_abs, self.backup_dir) if use_existing else []
            if items:
                done = migrate_legacy(self.store, items, password, name)
                migrated = len(done)
                for path in done:   # only now that every sealed copy checked out
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                acct = self.store.by_name(name) or self.store.by_address(
                    wallet_from_hex(items[0][0]).address)
            else:
                acct = self.store.add(name, new_key_hex(), password)
            key = open_vault(acct["vault"], password)
            out = self._login(acct, key)
            out["migrated"] = migrated
            return out

    def login(self, acct_id, password) -> dict:
        with self.wlock:
            acct = self.store.get(str(acct_id))
            if not acct:
                raise ValueError("That profile is not on this phone.")
            self.throttle.check(acct["id"])
            try:
                key = open_vault(acct["vault"], str(password or ""))
            except BadPassword:
                self.throttle.fail(acct["id"])
                raise
            self.throttle.ok(acct["id"])
            return self._login(acct, key)

    def _import(self, text: str, password: str, name=None) -> dict:
        d = parse_export(text)
        key = open_vault(d["vault"], str(password or ""))  # proves the password is right
        w = wallet_from_hex(key)
        if w.address != d["address"]:
            raise ValueError("This backup is damaged.")
        if self.store.by_address(w.address):
            raise ValueError("This account is already on this phone. Log in instead.")
        acct = self.store.add(name or d["name"], key, password, vault=d["vault"])
        return self._login(acct, key)

    def import_backup(self, text, password, name=None) -> dict:
        with self.wlock:
            self.throttle.check("import")
            try:
                return self._import(text, password, name or None)
            except BadPassword:
                self.throttle.fail("import")
                raise

    def remote_login(self, relay, name, password) -> dict:
        name = validate_name(name)
        with self.wlock:
            self.throttle.check("import")
            blob = relay_request(relay, relay_id(name, str(password or "")))
            try:
                return self._import(blob, password)
            except BadPassword:
                self.throttle.fail("import")
                raise

    def export_backup(self) -> dict:
        s = self._current()
        acct = self.store.get(s["id"])
        return {"backup": make_export(acct["name"], acct["address"], acct["vault"])}

    def show_key(self, password) -> dict:
        with self.wlock:
            return {"key": self._verify(password)[1]}

    def backup_online(self, password, relay) -> dict:
        with self.wlock:
            acct, _ = self._verify(password)
            if len(password) < 12:
                raise ValueError("To keep a copy on a node, use a password of at least 12 characters. Change it first under Change password.")
            relay_request(relay, relay_id(acct["name"], password),
                          make_export(acct["name"], acct["address"], acct["vault"]))
            return {"saved": True}

    def change_password(self, old, new) -> dict:
        with self.wlock:
            acct, key = self._verify(old)
            check_password_rules(new)
            self.store.set_vault(acct["id"], seal(key, new))
            return {"changed": True}

    def remove_account(self, password, confirm) -> dict:
        if confirm != "DELETE":
            raise ValueError("Type DELETE to confirm.")
        with self.wlock:
            acct, _ = self._verify(password)
            self.store.remove(acct["id"])
            return self.logout()


def make_handler(ui: UIState, port: int):
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"http://{h}" for h in hosts}
    routes = {
        "/api/send": lambda b: ui.send(b.get("to", ""), b.get("amount", ""), b.get("fee", "0")),
        "/api/auth/signup": lambda b: ui.signup(b.get("name"), b.get("password"), bool(b.get("use_existing"))),
        "/api/auth/login": lambda b: ui.login(b.get("id"), b.get("password")),
        "/api/auth/import": lambda b: ui.import_backup(b.get("backup"), b.get("password"), b.get("name")),
        "/api/auth/remote": lambda b: ui.remote_login(b.get("relay"), b.get("name"), b.get("password")),
        "/api/auth/logout": lambda b: ui.logout(),
        "/api/auth/ping": lambda b: {"ok": True},
        "/api/mining": lambda b: ui.set_mining(bool(b.get("on"))),
        "/api/account/export": lambda b: ui.export_backup(),
        "/api/account/key": lambda b: ui.show_key(b.get("password")),
        "/api/account/backup_online": lambda b: ui.backup_online(b.get("password"), b.get("relay")),
        "/api/account/password": lambda b: ui.change_password(b.get("old"), b.get("new")),
        "/api/account/remove": lambda b: ui.remove_account(b.get("password"), b.get("confirm")),
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body: bytes, ctype="application/json", cookie=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; "
                             "style-src 'unsafe-inline'; connect-src 'self'")
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj, cookie=None):
            self._send(code, json.dumps(obj).encode(), cookie=cookie)

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in hosts

        def _token(self):
            try:
                c = SimpleCookie(self.headers.get("Cookie", ""))
                return c[COOKIE].value if COOKIE in c else None
            except Exception:
                return None

        def do_GET(self):
            if not self._host_ok():
                return self._json(403, {"error": "bad host"})
            path = urlparse(self.path).path
            if path == "/":
                return self._send(200, HTML.encode(), "text/html; charset=utf-8")
            if path == "/api/state":
                return self._json(200, ui.state(self._token()))
            if path == "/favicon.ico":
                return self._send(204, b"")
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok():
                return self._json(403, {"error": "bad host"})
            origin = self.headers.get("Origin")
            path = urlparse(self.path).path
            if (path not in routes
                    or self.headers.get("X-Sthir-UI") != "1"
                    or not self.headers.get("Content-Type", "").startswith("application/json")
                    or (origin is not None and origin not in origins)):
                return self._json(403, {"error": "forbidden"})
            if path not in PUBLIC and not ui.authed(self._token()):
                return self._json(401, {"error": "locked"})
            try:
                n = int(self.headers.get("Content-Length", 0))
                if n > 8192:
                    raise ValueError("Request too large.")
                body = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("Bad request.")
                result = routes[path](body)
                if path not in PUBLIC:
                    ui.touch()
                cookie = None
                if isinstance(result, dict):
                    if "_token" in result:
                        cookie = f"{COOKIE}={result.pop('_token')}; Path=/; HttpOnly; SameSite=Strict"
                    if result.pop("_clear", False):
                        cookie = f"{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
                self._json(200, result, cookie)
            except PermissionError:
                self._json(401, {"error": "locked"})
            except Locked as e:
                self._json(429, {"error": str(e)})
            except BadPassword as e:
                self._json(403, {"error": str(e)})
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                self._json(400, {"error": str(e)})
            except OSError as e:
                self._json(500, {"error": f"Could not read or write the wallet files: {e}"})

    return Handler


HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>Sthir wallet</title>
<style>
:root{
  --paper:#E9EEF3; --sheet:#F8FAFC; --ink:#15213B; --ink-2:#47556F; --rule:#BCC7D3;
  --credit:#1D7553; --debit:#B8312A; --btn:#15213B; --btn-ink:#F2F5F9;
  --serif:ui-serif,"Iowan Old Style","Noto Serif",Georgia,serif;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans","Noto Sans Devanagari",sans-serif;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){
  :root{--paper:#0E131B; --sheet:#171F2B; --ink:#E7EDF5; --ink-2:#9BA9BD; --rule:#2A3646;
        --credit:#5FCBA2; --debit:#F2857C; --btn:#E7EDF5; --btn-ink:#0E131B;}
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 var(--sans)}
.wrap{max-width:560px;margin:0 auto;padding:0 20px}
button{font-family:inherit;cursor:pointer}
button:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid var(--ink);outline-offset:2px}

.top{position:sticky;top:0;z-index:5;background:var(--paper);border-bottom:1px solid var(--rule)}
.top .wrap{display:flex;align-items:center;justify-content:space-between;height:56px}
.mark{display:flex;align-items:baseline;gap:10px}
.dev{font-size:26px;font-weight:700;line-height:1}
.lat{font-family:var(--serif);font-size:15px;color:var(--ink-2)}
.status{display:flex;align-items:center;gap:8px;font-size:14px;color:var(--ink-2);font-variant-numeric:tabular-nums}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ink-2)}
.dot.ok{background:var(--credit)} .dot.bad{background:var(--debit)}

.banner{margin:16px 0 0;padding:12px 14px;background:var(--sheet);border-left:3px solid var(--debit);font-size:14px}
.banner code,.hint code{font-family:var(--mono);font-size:13px;word-break:break-all}

main{padding:24px 0 120px}
h2{font-family:var(--serif);font-size:20px;font-weight:600;margin:32px 0 12px}
.label{font-size:14px;color:var(--ink-2);margin:0 0 4px}
.total{display:inline-flex;align-items:baseline;gap:10px;border-bottom:4px double var(--ink);padding-bottom:6px;margin:4px 0 8px;max-width:100%}
#bal{font-family:var(--serif);font-size:clamp(44px,15vw,68px);font-weight:500;line-height:1.05;letter-spacing:-.01em;font-variant-numeric:lining-nums tabular-nums;overflow-wrap:anywhere}
.unit{font-size:18px;color:var(--ink-2)}
.sub{margin:0;color:var(--ink-2);font-size:14px;min-height:21px}
.addr-row{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:12px;margin:24px 0 28px}
.addr{font-family:var(--mono);font-size:13px;line-height:1.5;white-space:pre;display:block}

.primary{width:100%;min-height:52px;border:0;border-radius:10px;background:var(--btn);color:var(--btn-ink);font-size:17px;font-weight:600}
.primary[disabled]{opacity:.6}
.ghost{min-height:44px;padding:0 16px;border:1px solid var(--ink);background:transparent;color:var(--ink);border-radius:10px;font-size:15px;font-weight:600}
.link{background:none;border:0;color:var(--ink);text-decoration:underline;font-size:15px;font-weight:600;min-height:44px;padding:0 4px}
.seeall{display:block;margin:8px 0 0 auto}

.rows{list-style:none;margin:0;padding:0;border-top:1px solid var(--rule)}
.row{display:grid;grid-template-columns:56px 1fr auto;min-height:64px;border-bottom:1px solid var(--rule)}
.no{display:flex;align-items:center;justify-content:flex-end;padding-right:10px;border-right:3px double var(--ink-2);font-family:var(--serif);font-size:14px;color:var(--ink-2);font-variant-numeric:tabular-nums}
.mid{padding:10px 12px;min-width:0}
.t{font-weight:600}
.s{font-size:13px;color:var(--ink-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mono{font-family:var(--mono)}
.amt{align-self:center;font-family:var(--serif);font-size:18px;font-variant-numeric:lining-nums tabular-nums;text-align:right}
.right{align-self:center;text-align:right;font-size:13px;color:var(--ink-2)}
.credit{color:var(--credit)} .debit{color:var(--debit)}
.empty{color:var(--ink-2);margin:0}
pre{margin:12px 0;padding:12px;background:var(--sheet);border:1px solid var(--rule);border-radius:8px;overflow-x:auto;font-family:var(--mono);font-size:13px;white-space:pre-wrap;word-break:break-all}

.stat{display:flex;justify-content:space-between;gap:16px;padding:14px 0;border-bottom:1px solid var(--rule)}
.stats{border-top:1px solid var(--rule)}
.stat b{font-family:var(--serif);font-size:18px;font-weight:500;font-variant-numeric:lining-nums tabular-nums}

.tabbar{position:fixed;left:0;right:0;bottom:0;z-index:6;background:var(--paper);border-top:1px solid var(--rule);padding-bottom:env(safe-area-inset-bottom)}
.tabbar .wrap{display:grid;grid-template-columns:repeat(4,1fr);padding:0}
.tab-btn{height:56px;border:0;background:none;color:var(--ink-2);font-size:15px;font-weight:600}
.tab-btn[aria-selected=true]{color:var(--ink);box-shadow:inset 0 3px 0 var(--ink)}

.scrim{position:fixed;inset:0;z-index:10;background:rgba(10,16,28,.5);opacity:0;pointer-events:none;transition:opacity .18s}
.scrim.open{opacity:1;pointer-events:auto}
.sheet{position:fixed;left:0;right:0;bottom:0;z-index:20;margin:0 auto;max-width:560px;max-height:92vh;overflow:auto;background:var(--sheet);border-radius:16px 16px 0 0;padding:20px 20px calc(24px + env(safe-area-inset-bottom));transform:translateY(100%);visibility:hidden;transition:transform .22s ease,visibility 0s .22s}
.sheet.open{transform:none;visibility:visible;transition:transform .22s ease,visibility 0s}
.sheet h2{margin:0 0 4px}
label{display:block;font-size:14px;font-weight:600;margin:16px 0 6px}
input,textarea{width:100%;min-height:48px;padding:12px;border:1px solid var(--ink-2);border-radius:8px;background:var(--paper);color:var(--ink);font:16px var(--sans)}
textarea{font-family:var(--mono);font-size:14px;resize:none}
.field-row{display:flex;justify-content:flex-end;gap:8px}
.amt-row{display:flex;gap:8px;align-items:center}
.hint{font-size:13px;color:var(--ink-2);margin:6px 0 0}
.err{color:var(--debit);font-size:14px;min-height:21px;margin:12px 0}
.big{font-family:var(--serif);font-size:44px;line-height:1.1;font-variant-numeric:lining-nums tabular-nums;margin:12px 0 4px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:10px 16px;margin:16px 0}
.kv dt{color:var(--ink-2)} .kv dd{margin:0;text-align:right;font-variant-numeric:tabular-nums;min-width:0}
.kv dd.addrfull{font-family:var(--mono);font-size:13px;word-break:break-all;text-align:left;grid-column:1/-1;background:var(--paper);padding:10px;border-radius:8px}
.stack{display:grid;gap:10px}
.toast{position:fixed;left:50%;bottom:76px;z-index:30;transform:translateX(-50%);background:var(--ink);color:var(--btn-ink);padding:10px 16px;border-radius:8px;font-size:14px;opacity:0;pointer-events:none;transition:opacity .2s}
.toast.show{opacity:1}
.minecard{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:16px 0 0;padding:12px 14px;border:1px solid var(--ink-2);border-radius:10px}
.minecard button[aria-pressed=true]{background:var(--ink);color:var(--paper)}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.actions .ghost{min-height:52px;font-size:17px}
.qr{width:min(72vw,280px);margin:12px auto;padding:10px;background:#fff;border-radius:12px;line-height:0}
.qr svg{width:100%;height:auto;display:block}
.center{text-align:center}
.cam{position:relative;aspect-ratio:1/1;margin:12px 0;background:#000;border-radius:12px;overflow:hidden}
.cam video{width:100%;height:100%;object-fit:cover;display:block}
.cam i{position:absolute;inset:18%;border:3px solid #fff;border-radius:12px;box-shadow:0 0 0 999px rgba(0,0,0,.35);pointer-events:none}
.opts{list-style:none;margin:0;padding:0;border-top:1px solid var(--rule)}
.opt{display:block;width:100%;text-align:left;padding:16px 0;border:0;border-bottom:1px solid var(--rule);background:none;color:var(--ink);font:inherit}
.opt .t{display:block;font-weight:600;font-size:17px}
.opt .s{display:block;color:var(--ink-2);font-size:14px;margin-top:2px;white-space:normal;overflow:visible;text-overflow:clip}
.opt.off{color:var(--ink-2)}
.opt.off .t{color:var(--ink)}
.keybox{font-family:var(--mono);font-size:13px;word-break:break-all;background:var(--paper);padding:12px;border-radius:8px;border:1px solid var(--ink-2);user-select:all}
.warnbox{border-left:4px solid var(--debit);padding:4px 0 4px 12px;margin:14px 0}
.wlist{list-style:none;margin:12px 0 0;padding:0;border-top:1px solid var(--rule)}
.wlist li{display:flex;align-items:center;gap:12px;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--rule)}
.wlist .a{min-width:0;font-family:var(--mono);font-size:14px;overflow-wrap:anywhere}
.wlist .d{display:block;font-family:var(--sans);font-size:13px;color:var(--ink-2)}
.auth{position:fixed;inset:0;z-index:40;background:var(--paper);overflow:auto;padding-bottom:env(safe-area-inset-bottom)}
.auth .wrap{padding-top:20px;padding-bottom:40px}
.auth h1{font-family:var(--serif);font-size:30px;font-weight:500;margin:28px 0 6px}
.alinks{display:flex;flex-wrap:wrap;gap:0 16px;margin-top:12px}
.chk{display:flex;gap:12px;align-items:flex-start;font-weight:400;margin:18px 0 0}
input[type=checkbox]{width:22px;height:22px;min-height:22px;flex:none;margin-top:3px}
.seg{display:grid;grid-template-columns:1fr 1fr;margin:16px 0 4px;border:1px solid var(--ink);border-radius:10px;overflow:hidden}
.seg button{min-height:44px;border:0;background:transparent;color:var(--ink);font-weight:600;font-size:15px}
.seg button[aria-pressed=true]{background:var(--ink);color:var(--paper)}
.opt[aria-pressed=true]{box-shadow:inset 4px 0 0 var(--ink);padding-left:14px}
.opt[aria-pressed]{cursor:pointer}
.note{color:var(--ink-2);font-size:14px}
@media (prefers-reduced-motion:reduce){.sheet,.scrim,.toast{transition:none}}
</style>
</head>
<body>
<header class="top"><div class="wrap">
  <div class="mark"><span class="dev" lang="hi">स्थिर</span><span class="lat">Sthir</span></div>
  <div class="status"><span class="dot" id="dot"></span><span id="hdrText">Connecting</span></div>
</div></header>

<div class="wrap">
  <div id="banner" class="banner" role="status" hidden></div>

  <main>
    <section id="tab-wallet" aria-label="Wallet">
      <p class="label">Balance<span id="who"></span></p>
      <div class="total"><span id="bal">&mdash;</span><span class="unit">coins</span></div>
      <p class="sub" id="balSub"></p>

      <div class="addr-row">
        <div><p class="label">Your address</p><code class="addr" id="addr"></code></div>
        <button class="ghost" id="copyAddr">Copy</button>
      </div>

      <div class="actions"><button class="primary" id="openSend">Send</button><button class="ghost" id="openReceive">Receive</button></div>

      <div class="minecard" id="mineCard" hidden>
        <div><p class="label" style="margin:0">Mining</p><p class="hint" id="mineSub" style="margin:2px 0 0"></p></div>
        <button class="ghost" id="mineBtn" aria-pressed="false">Start</button>
      </div>
      <p class="err" id="mineErr" role="alert"></p>

      <div id="pendingBox" hidden>
        <h2>Waiting for a miner</h2>
        <ul class="rows" id="pendingList"></ul>
      </div>

      <div id="emptyBox" hidden>
        <h2>No coins yet</h2>
        <p class="empty">Coins arrive by mining or when someone sends them to your address. To mine to this wallet, start a miner:</p>
        <pre id="mineCmd"></pre>
        <button class="ghost" id="copyCmd">Copy command</button>
      </div>

      <div id="latestBox" hidden>
        <h2>Latest</h2>
        <ul class="rows" id="latestList"></ul>
        <button class="link seeall" id="seeAll">See full ledger</button>
      </div>
    </section>

    <section id="tab-ledger" aria-label="Ledger" hidden>
      <h2 style="margin-top:0">Ledger</h2>
      <ul class="rows" id="ledgerList"></ul>
      <p class="empty" id="ledgerEmpty" hidden>Nothing here yet. Mined, sent and received coins will be listed with their block number.</p>
    </section>

    <section id="tab-network" aria-label="Network" hidden>
      <h2 style="margin-top:0">Network</h2>
      <div class="stats" id="stats"></div>
      <h2>Latest blocks</h2>
      <ul class="rows" id="blockList"></ul>
      <h2>Peers</h2>
      <ul class="rows" id="peerList"></ul>
      <p class="empty" id="peerEmpty" hidden>No peers yet. This node is running alone. Start another node with <code class="mono">--peer</code> pointing at it.</p>
    </section>

    <section id="tab-more" aria-label="More" hidden>
      <h2 style="margin-top:0">More</h2>
      <ul class="opts">
        <li><button class="opt" id="moScan"><span class="t">Scan to pay</span><span class="s">Scan a Sthir QR code to fill in the address and amount.</span></button></li>
        <li><button class="opt" id="moReq"><span class="t">Request payment</span><span class="s">Show a QR code with your address and an amount for someone to scan.</span></button></li>
        <li><button class="opt" id="moWallet"><span class="t">Account</span><span class="s">Back up this profile, change its password, switch profile or log out.</span></button></li>
        <li><div class="opt off"><span class="t">Trade</span><span class="s">Not available yet. Trading needs a chain that survives restarts, and escrow so a seller can't take your payment and keep the coins.</span></div></li>
      </ul>
    </section>
  </main>
</div>

<nav class="tabbar" aria-label="Sections"><div class="wrap" role="tablist">
  <button class="tab-btn" role="tab" data-tab="wallet" aria-selected="true">Wallet</button>
  <button class="tab-btn" role="tab" data-tab="ledger" aria-selected="false">Ledger</button>
  <button class="tab-btn" role="tab" data-tab="network" aria-selected="false">Network</button>
  <button class="tab-btn" role="tab" data-tab="more" aria-selected="false">More</button>
</div></nav>

<div class="scrim" id="scrim"></div>
<div class="sheet" id="sheet" role="dialog" aria-modal="true" aria-labelledby="sheetTitle"><div id="sheetBody"></div></div>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<div class="auth" id="auth" hidden><div class="wrap"><div id="authBody"></div></div></div>

<script>
(() => {
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const UNIT = 1e8;
let S = null, tab = 'wallet';
let sheet = {open:false, step:'form', to:'', amt:'', fee:'0.001', err:'', sending:false, txid:'', ramt:''};

function fmt(u, minFrac = 2) {
  const neg = u < 0; u = Math.abs(Math.round(u));
  const whole = Math.floor(u / UNIT);
  const frac = String(u % UNIT).padStart(8, '0').replace(/0+$/, '').padEnd(minFrac, '0');
  return (neg ? '-' : '') + whole.toLocaleString('en-IN') + '.' + frac;
}
function plain(u) {
  const frac = String(u % UNIT).padStart(8, '0').replace(/0+$/, '');
  return Math.floor(u / UNIT) + (frac ? '.' + frac : '');
}
function parseUnits(str) {
  const m = /^(\d+)(?:\.(\d{1,8}))?$/.exec(String(str).trim());
  if (!m) return null;
  const u = Number(m[1]) * UNIT + Number((m[2] || '').padEnd(8, '0'));
  return Number.isSafeInteger(u) ? u : null;
}
const short = (a) => a ? a.slice(0, 8) + '…' + a.slice(-8) : '';
/* QR-BEGIN */
function qrEncode(text) {
  // QR Model 2, byte mode, error correction level M, versions 1-6 (up to 106 bytes).
  const bytes = Array.from(new TextEncoder().encode(text));
  const DATA = [0, 16, 28, 44, 64, 86, 108];  // data codewords per version
  const ECB = [0, 10, 16, 26, 18, 24, 16];    // error-correction codewords per block
  const NBLK = [0, 1, 1, 1, 2, 2, 4];         // blocks per version
  const ALIGN = [[], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34]];
  let ver = 1;
  while (ver <= 6 && bytes.length > DATA[ver] - 2) ver++;
  if (ver > 6) throw new Error('QR text too long');
  const size = 17 + 4 * ver;

  // 1. Data bits: mode, length, bytes, terminator, padding.
  const bits = [];
  const put = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
  put(4, 4); put(bytes.length, 8); bytes.forEach((b) => put(b, 8));
  const cap = DATA[ver] * 8;
  put(0, Math.min(4, cap - bits.length));
  while (bits.length % 8) bits.push(0);
  for (let pad = 0xEC; bits.length < cap; pad ^= 0xEC ^ 0x11) put(pad, 8);
  const cw = [];
  for (let i = 0; i < bits.length; i += 8) cw.push(parseInt(bits.slice(i, i + 8).join(''), 2));

  // 2. Reed-Solomon error correction over GF(256), blocks interleaved.
  const EXP = new Array(512), LOG = new Array(256);
  for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 256) x ^= 0x11D; }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
  const ecn = ECB[ver];
  let gen = [1];
  for (let i = 0; i < ecn; i++) {
    const next = new Array(gen.length + 1).fill(0);
    gen.forEach((c, j) => { next[j] ^= c; next[j + 1] ^= mul(c, EXP[i]); });
    gen = next;
  }
  const per = DATA[ver] / NBLK[ver];
  const dBlocks = [], eBlocks = [];
  for (let b = 0; b < NBLK[ver]; b++) {
    const d = cw.slice(b * per, (b + 1) * per);
    const r = new Array(ecn).fill(0);
    for (const v of d) {
      const f = v ^ r.shift(); r.push(0);
      if (f) for (let i = 0; i < ecn; i++) r[i] ^= mul(gen[i + 1], f);
    }
    dBlocks.push(d); eBlocks.push(r);
  }
  const all = [];
  for (let i = 0; i < per; i++) dBlocks.forEach((d) => all.push(d[i]));
  for (let i = 0; i < ecn; i++) eBlocks.forEach((e) => all.push(e[i]));
  const dbits = [];
  all.forEach((c) => { for (let i = 7; i >= 0; i--) dbits.push((c >>> i) & 1); });

  // 3. Function patterns: timing, finders, alignment, format info.
  const m = Array.from({ length: size }, () => new Array(size).fill(false));
  const fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const setFn = (x, y, v) => { m[y][x] = v; fn[y][x] = true; };
  for (let i = 0; i < size; i++) { setFn(6, i, i % 2 === 0); setFn(i, 6, i % 2 === 0); }
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x >= 0 && x < size && y >= 0 && y < size) {
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        setFn(x, y, d !== 2 && d !== 4);
      }
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  const pos = ALIGN[ver];
  for (const cy of pos) for (const cx of pos) {
    if ((cx === 6 && cy === 6) || (cx === 6 && cy === size - 7) || (cx === size - 7 && cy === 6)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
      setFn(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  const drawFormat = (mask) => {
    const data = mask;  // error correction level M is 00
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const f = ((data << 10) | rem) ^ 0x5412;
    const bit = (i) => ((f >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) setFn(8, i, bit(i));
    setFn(8, 7, bit(6)); setFn(8, 8, bit(7)); setFn(7, 8, bit(8));
    for (let i = 9; i < 15; i++) setFn(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) setFn(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) setFn(8, size - 15 + i, bit(i));
    setFn(8, size - 8, true);
  };
  drawFormat(0);

  // 4. Place data bits in the zigzag order.
  let k = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j;
      const y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
      if (!fn[y][x] && k < dbits.length) m[y][x] = dbits[k++] === 1;
    }
  }

  // 5. Choose the mask with the lowest penalty.
  const MASKS = [
    (x, y) => (x + y) % 2 === 0,
    (x, y) => y % 2 === 0,
    (x, y) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
    (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
    (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];
  const applyMask = (mask) => {
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++)
      if (!fn[y][x] && MASKS[mask](x, y)) m[y][x] = !m[y][x];
  };
  const penalty = () => {
    let p = 0;
    for (let i = 0; i < size; i++) {
      for (const s of [m[i].map(Number).join(''), m.map((r) => Number(r[i])).join('')]) {
        for (const run of s.match(/0+|1+/g)) if (run.length >= 5) p += 3 + (run.length - 5);
        p += 40 * ((s.match(/(?=00001011101)/g) || []).length + (s.match(/(?=10111010000)/g) || []).length);
      }
    }
    for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++) {
      const c = m[y][x];
      if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) p += 3;
    }
    let dark = 0;
    m.forEach((r) => r.forEach((v) => { if (v) dark++; }));
    const total = size * size;
    return p + 10 * Math.max(0, Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1);
  };
  let best = 0, bestP = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(mask); drawFormat(mask);
    const p = penalty();
    if (p < bestP) { best = mask; bestP = p; }
    applyMask(mask);
  }
  applyMask(best); drawFormat(best);
  return m;
}

function qrSvg(text) {
  const m = qrEncode(text), n = m.length, q = 4;
  let d = '';
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++)
    if (m[y][x]) d += 'M' + (x + q) + ',' + (y + q) + 'h1v1h-1z';
  const s = n + 2 * q;
  return '<svg viewBox="0 0 ' + s + ' ' + s + '" xmlns="http://www.w3.org/2000/svg" role="img" ' +
    'aria-label="QR code" shape-rendering="crispEdges"><rect width="' + s + '" height="' + s +
    '" fill="#fff"/><path d="' + d + '" fill="#000"/></svg>';
}
function qrPng(text) {
  // Drawn straight onto a canvas from the QR matrix: no image loading (the page's CSP blocks images).
  const m = qrEncode(text), n = m.length, q = 4, cells = n + 2 * q;
  const scale = Math.max(4, Math.floor(1024 / cells)), px = cells * scale;
  const c = document.createElement('canvas'); c.width = c.height = px;
  const g = c.getContext('2d');
  g.fillStyle = '#fff'; g.fillRect(0, 0, px, px); g.fillStyle = '#000';
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++)
    if (m[y][x]) g.fillRect((x + q) * scale, (y + q) * scale, scale, scale);
  return new Promise((res, rej) => c.toBlob((b) => b ? res(b) : rej(new Error('no image')), 'image/png'));
}
/* QR-END */

function parsePayment(t) {
  // Accepts "sthir:<64 hex>[?amount=1.5]" or a bare 64-character address.
  const m = /^(?:sthir:)?([0-9a-fA-F]{64})(?:\?(.*))?$/.exec(String(t || '').trim());
  if (!m) return null;
  let amount = '';
  if (m[2]) {
    const a = /(?:^|&)amount=(\d+(?:\.\d{1,8})?)(?:&|$)/.exec(m[2]);
    if (a && parseUnits(a[1]) > 0) amount = a[1];
  }
  return {to: m[1].toLowerCase(), amount};
}

function fmtBig(n) {
  if (n < 1e3) return String(Math.round(n));
  if (n < 1e6) return (n / 1e3).toFixed(1) + 'K';
  if (n < 1e9) return (n / 1e6).toFixed(1) + 'M';
  if (n < 1e12) return (n / 1e9).toFixed(1) + 'G';
  return (n / 1e12).toFixed(1) + 'T';
}
function ago(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 10) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 2200);
}
async function copy(text, msg) {
  try { await navigator.clipboard.writeText(text); }
  catch (e) {
    const ta = document.createElement('textarea'); ta.value = text;
    document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
  }
  toast(msg);
}

function ledgerRow(e) {
  const titles = {mined: 'Mined', sent: 'Sent', received: 'Received'};
  const debit = e.kind === 'sent';
  let line = '';
  if (e.kind === 'sent') line = 'To ' + short(e.peer);
  else if (e.kind === 'received') line = 'From ' + short(e.peer);
  else line = 'Block reward and fees';
  const when = ago(e.ts) + (e.fee ? ', fee ' + fmt(e.fee, 3) : '');
  return `<li class="row"><div class="no">${esc(e.height)}</div>
    <div class="mid"><div class="t">${titles[e.kind]}</div>
    <div class="s ${e.kind === 'mined' ? '' : 'mono'}">${esc(line)}</div><div class="s">${esc(when)}</div></div>
    <div class="amt ${debit ? 'debit' : 'credit'}">${debit ? '−' : '+'}${fmt(e.amount)}</div></li>`;
}
function blockRow(b) {
  const who = b.mine ? 'Mined by you' : 'Miner ' + short(b.miner);
  return `<li class="row"><div class="no">${esc(b.height)}</div>
    <div class="mid"><div class="t mono" style="font-size:14px">${esc(b.hash.slice(0, 16))}</div><div class="s">${esc(who)}</div></div>
    <div class="right">${b.txs} ${b.txs === 1 ? 'payment' : 'payments'}<br>${esc(ago(b.ts))}</div></li>`;
}
function pendingRow(p) {
  return `<li class="row"><div class="no">Next</div>
    <div class="mid"><div class="t">Sending</div><div class="s mono">To ${esc(short(p.to))}</div><div class="s">Fee ${fmt(p.fee, 3)}</div></div>
    <div class="amt debit">−${fmt(p.amount)}</div></li>`;
}

function render() {
  if (!S) return;
  if (S.locked) { showAuth(); return; }
  hideAuth(); wasUnlocked = true;
  const ok = S.node_ok;
  $('#dot').className = 'dot ' + (S.ui_down ? 'bad' : ok ? 'ok' : 'bad');
  $('#hdrText').textContent = S.ui_down ? 'Disconnected' : ok ? 'Block ' + S.status.height.toLocaleString('en-IN') : 'Node offline';
  const ban = $('#banner');
  if (S.ui_down) {
    ban.hidden = false;
    ban.innerHTML = '<strong>This page lost its wallet server.</strong> Check that <code>sthir_ui.py</code> is still running in Termux. Your coins are not affected.';
  } else if (!ok) {
    ban.hidden = false;
    ban.innerHTML = `<strong>Can't reach the node.</strong> Your coins are not affected. Start the node at <code>${esc(S.node)}</code>, or restart this wallet with the right <code>--node</code> address. This page retries every few seconds.`;
  } else ban.hidden = true;

  $('#who').textContent = S.account ? ' · ' + S.account.name : '';
  $('#addr').textContent = S.address ? S.address.slice(0, 32) + '\n' + S.address.slice(32) : '';
  const pend = S.pending || [], ledger = S.ledger || [];
  $('#bal').textContent = ok ? fmt(S.balance) : '—';
  $('#balSub').textContent = ok && pend.length
    ? fmt(S.available) + ' available. ' + fmt(S.balance - S.available) + ' is waiting for a miner.' : '';

  const mc = $('#mineCard'), on = !!S.mining_on;
  mc.hidden = !ok;
  $('#mineBtn').setAttribute('aria-pressed', on);
  $('#mineBtn').textContent = on ? 'Stop' : 'Start';
  $('#mineSub').textContent = on ? 'On. New coins from blocks you find come to this wallet.' : 'Off. This phone is not making blocks.';
  $('#pendingBox').hidden = !pend.length;
  $('#pendingList').innerHTML = pend.map(pendingRow).join('');
  const empty = ok && S.balance === 0 && !ledger.length && !pend.length;
  $('#emptyBox').hidden = !empty;
  if (empty) $('#mineCmd').textContent =
    `python sthir_net.py node --port 5003 --peer ${S.node} --mine ${S.address} --bits ${S.status.bits} --block-time ${S.status.block_time} --retarget ${S.status.retarget}`;
  $('#latestBox').hidden = !ledger.length;
  $('#latestList').innerHTML = ledger.slice(0, 3).map(ledgerRow).join('');

  $('#ledgerList').innerHTML = ledger.map(ledgerRow).join('');
  $('#ledgerEmpty').hidden = !!ledger.length;

  if (ok) {
    const st = S.status;
    $('#stats').innerHTML = [
      ['Block height', st.height.toLocaleString('en-IN')],
      ['Coins in circulation', fmt(st.supply)],
      ['Mining difficulty', fmtBig(st.difficulty) + ' hashes per block'],
      ['Block time', st.avg_block_time == null ? 'Measuring' : st.avg_block_time.toFixed(1) + ' s, target ' + st.block_time + ' s'],
      ['Next adjustment', 'in ' + st.blocks_to_retarget + (st.blocks_to_retarget === 1 ? ' block' : ' blocks')],
      ['Peers', st.peers],
      ['Payments waiting', st.mempool],
    ].map(([k, v]) => `<div class="stat"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('');
    $('#blockList').innerHTML = (S.blocks || []).map(blockRow).join('');
    $('#peerList').innerHTML = (S.peers || []).map((p) =>
      `<li class="row" style="grid-template-columns:1fr"><div class="mid mono" style="font-size:14px;overflow-wrap:anywhere">${esc(p)}</div></li>`).join('');
    $('#peerEmpty').hidden = !!(S.peers || []).length;
  }
}

function setTab(t) {
  tab = t;
  for (const id of ['wallet', 'ledger', 'network', 'more']) $('#tab-' + id).hidden = id !== t;
  document.querySelectorAll('.tab-btn').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === t)));
  window.scrollTo(0, 0);
}
document.querySelectorAll('.tab-btn').forEach((b) => b.addEventListener('click', () => setTab(b.dataset.tab)));
$('#seeAll').addEventListener('click', () => setTab('ledger'));
$('#copyAddr').addEventListener('click', () => S && copy(S.address, 'Address copied'));
$('#mineBtn').addEventListener('click', async (e) => {
  const b = e.target, want = b.getAttribute('aria-pressed') !== 'true';
  b.disabled = true; $('#mineErr').textContent = '';
  try { await api('/api/mining', {on: want}); await poll(); }
  catch (x) { $('#mineErr').textContent = x.message; }
  b.disabled = false;
});
$('#copyCmd').addEventListener('click', () => copy($('#mineCmd').textContent, 'Command copied'));

/* ---- send sheet ---- */
function validate() {
  if (!S || !S.node_ok) return 'The node is offline. Try again when the top right shows a block number.';
  const to = sheet.to.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(to)) return `Address must be 64 characters using 0-9 and a-f. You entered ${to.length}.`;
  const amt = parseUnits(sheet.amt);
  if (amt === null || amt <= 0) return 'Enter an amount greater than 0, with up to 8 decimals.';
  const fee = parseUnits(sheet.fee);
  if (fee === null) return 'Enter the fee as a number, for example 0.001.';
  if (amt + fee > S.available) return `Not enough coins. With this fee you can send up to ${fmt(Math.max(S.available - fee, 0))}.`;
  return '';
}
function drawSheet() {
  stopScan();
  const body = $('#sheetBody');
  if (sheet.step === 'form') {
    body.innerHTML = `<h2 id="sheetTitle">Send</h2>
      <label for="f-to">To</label>
      <textarea id="f-to" rows="3" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="Paste the 64-character address">${esc(sheet.to)}</textarea>
      <div class="field-row"><button class="link" id="scan" type="button">Scan QR</button><button class="link" id="photo" type="button">Photo</button><button class="link" id="paste" type="button">Paste</button></div>
      <label for="f-amt">Amount</label>
      <div class="amt-row"><input id="f-amt" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${esc(sheet.amt)}"><button class="link" id="max" type="button">Max</button></div>
      <label for="f-fee">Fee</label>
      <input id="f-fee" inputmode="decimal" autocomplete="off" value="${esc(sheet.fee)}">
      <p class="hint">The fee goes to the miner who includes your payment.</p>
      <p class="err" id="err" role="alert">${esc(sheet.err)}</p>
      <button class="primary" id="review">Review</button>`;
    $('#f-to').addEventListener('input', (e) => sheet.to = e.target.value);
    $('#f-amt').addEventListener('input', (e) => sheet.amt = e.target.value);
    $('#f-fee').addEventListener('input', (e) => sheet.fee = e.target.value);
    $('#paste').addEventListener('click', async () => {
      try { sheet.to = (await navigator.clipboard.readText()).trim(); $('#f-to').value = sheet.to; }
      catch (e) { $('#err').textContent = 'Your browser blocked paste. Long-press the box and choose Paste.'; }
    });
    $('#scan').addEventListener('click', () => { sheet.step = 'scan'; drawSheet(); runScan(); });
    $('#photo').addEventListener('click', () => { sheet.step = 'scan'; drawSheet(); $('#scanFile').click(); });
    $('#max').addEventListener('click', () => {
      const fee = parseUnits(sheet.fee) ?? 0, room = (S ? S.available : 0) - fee;
      if (room <= 0) { $('#err').textContent = 'No coins available after the fee.'; return; }
      sheet.amt = plain(room); $('#f-amt').value = sheet.amt;
    });
    $('#review').addEventListener('click', () => {
      sheet.err = validate();
      if (sheet.err) { $('#err').textContent = sheet.err; return; }
      sheet.to = sheet.to.trim().toLowerCase(); sheet.step = 'review'; drawSheet();
    });
  } else if (sheet.step === 'review') {
    const amt = parseUnits(sheet.amt), fee = parseUnits(sheet.fee);
    const head = sheet.to.slice(0, -6), tail = sheet.to.slice(-6);
    body.innerHTML = `<h2 id="sheetTitle">Check before sending</h2>
      <div class="big">${fmt(amt)} <span class="unit">coins</span></div>
      <dl class="kv">
        <dt>To</dt><dd class="addrfull">${esc(head)}<strong>${esc(tail)}</strong></dd>
        <dt>Fee</dt><dd>${fmt(fee, 3)}</dd>
        <dt>Total</dt><dd><strong>${fmt(amt + fee, 3)}</strong></dd>
      </dl>
      <p class="hint">Payments cannot be reversed. Compare the last 6 characters with the address you were given.</p>
      <p class="err" id="err" role="alert">${esc(sheet.err)}</p>
      <div class="stack"><button class="primary" id="confirm">Send ${fmt(amt)} coins</button>
      <button class="ghost" id="back">Edit</button></div>`;
    $('#back').addEventListener('click', () => { sheet.err = ''; sheet.step = 'form'; drawSheet(); });
    $('#confirm').addEventListener('click', doSend);
  } else if (sheet.step === 'scan') {
    body.innerHTML = `<h2 id="sheetTitle">Scan QR</h2>
      <div class="cam"><video id="cam" playsinline muted></video><i aria-hidden="true"></i></div>
      <p class="hint" id="scanMsg" role="status">Point the camera at a Sthir QR code, or pick a saved picture of one.</p>
      <button class="ghost" id="scanPick" style="width:100%;margin-bottom:8px">Choose from gallery</button>
      <input type="file" id="scanFile" accept="image/*" hidden>
      <button class="ghost" id="scanCancel" style="width:100%">Cancel</button>`;
    $('#scanCancel').addEventListener('click', () => { sheet.step = 'form'; drawSheet(); });
    $('#scanPick').addEventListener('click', () => $('#scanFile').click());
    $('#scanFile').addEventListener('change', (e) => { const f = e.target.files && e.target.files[0]; e.target.value = ''; if (f) scanPicture(f); });
  } else if (sheet.step === 'receive') {
    drawReceive(body);
  } else if (sheet.step.startsWith('a')) {
    drawAccount(body);
  } else {
    body.innerHTML = `<h2 id="sheetTitle">Sent</h2>
      <p>Your payment is waiting for a miner to put it in the next block. It will appear in your ledger once that happens.</p>
      <p class="hint mono">Payment ${esc(sheet.txid.slice(0, 16))}</p>
      <button class="primary" id="done" style="margin-top:20px">Done</button>`;
    $('#done').addEventListener('click', closeSheet);
  }
}
let scanStop = null, scanToken = 0;
function stopScan() {
  scanToken++;
  if (scanStop) { scanStop(); scanStop = null; }
}
async function runScan() {
  const token = ++scanToken;
  const say = (t, bad) => {
    const el = $('#scanMsg');
    if (el && token === scanToken) { el.textContent = t; el.className = bad ? 'err' : 'hint'; }
  };
  const unsupported = "This browser can't scan QR codes. Use Chrome on Android, or scan with another app and paste the address.";
  if (!('BarcodeDetector' in window) || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    say(unsupported, true); return;
  }
  let det, stream;
  try { det = new BarcodeDetector({formats: ['qr_code']}); }
  catch (e) { say(unsupported, true); return; }
  try { stream = await navigator.mediaDevices.getUserMedia({video: {facingMode: {ideal: 'environment'}}, audio: false}); }
  catch (e) { say('Camera access is blocked. Allow the camera for this site in your browser settings, then try again.', true); return; }
  const video = $('#cam');
  if (token !== scanToken || !video) { stream.getTracks().forEach((t) => t.stop()); return; }
  video.srcObject = stream;
  try { await video.play(); } catch (e) {}
  scanStop = () => stream.getTracks().forEach((t) => t.stop());
  while (token === scanToken) {
    try {
      for (const c of await det.detect(video)) {
        const r = parsePayment(c.rawValue);
        if (!r) { say('That QR code is not a Sthir address.', true); continue; }
        stopScan();
        sheet.to = r.to; if (r.amount) sheet.amt = r.amount;
        sheet.err = ''; sheet.step = 'form'; drawSheet();
        toast(r.amount ? 'Address and amount filled in' : 'Address filled in');
        return;
      }
    } catch (e) {}
    await new Promise((res) => setTimeout(res, 250));
  }
}
async function scanPicture(file) {
  const say = (t, bad) => { const el = $('#scanMsg'); if (el) { el.textContent = t; el.className = bad ? 'err' : 'hint'; } };
  stopScan();
  if (!('BarcodeDetector' in window)) { say("This browser can't read QR codes from a picture. Use Chrome on Android, or scan the code with another app and paste the address.", true); return; }
  let det, bmp;
  try { det = new BarcodeDetector({formats: ['qr_code']}); } catch (e) { say("This browser can't read QR codes from a picture.", true); return; }
  try { bmp = await createImageBitmap(file); } catch (e) { say('That file is not a picture this browser can open.', true); return; }
  say('Reading the picture…');
  const attempts = [bmp];
  const big = Math.max(bmp.width, bmp.height);
  if (big > 1600) {                                       // phone photos are huge; a smaller copy is often read faster and better
    const k = 1600 / big, c = document.createElement('canvas');
    c.width = Math.round(bmp.width * k); c.height = Math.round(bmp.height * k);
    c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
    attempts.unshift(c);
  }
  let sawQr = false;
  for (const src of attempts) {
    let found = [];
    try { found = await det.detect(src); } catch (e) {}
    for (const c of found) {
      sawQr = true;
      const r = parsePayment(c.rawValue);
      if (!r) continue;
      sheet.to = r.to; if (r.amount) sheet.amt = r.amount;
      sheet.err = ''; sheet.step = 'form'; drawSheet();
      toast(r.amount ? 'Address and amount filled in' : 'Address filled in');
      return;
    }
  }
  say(sawQr ? 'That QR code is not a Sthir address.' : 'No QR code found in that picture. Pick a sharper, closer one.', true);
}
function drawReceive(body) {
  if (!S || !S.address) {
    body.innerHTML = '<h2 id="sheetTitle">Receive</h2><p class="empty">The wallet is still loading. Try again in a moment.</p><button class="ghost" id="rdone" style="width:100%;margin-top:16px">Close</button>';
    $('#rdone').addEventListener('click', closeSheet);
    return;
  }
  body.innerHTML = `<h2 id="sheetTitle">Receive</h2>
    <p class="hint">The sender opens Send, taps Scan QR and points the camera at this code, or taps Photo and picks a saved copy of it.</p>
    <div class="qr" id="qrbox"></div>
    <code class="addr center" id="raddr"></code>
    <label for="r-amt">Amount to request (optional)</label>
    <input id="r-amt" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${esc(sheet.ramt)}">
    <p class="err" id="rerr" role="alert"></p>
    <div class="actions" style="margin-bottom:10px"><button class="ghost" id="rsave">Save picture</button><button class="ghost" id="rshare">Share</button></div>
    <div class="stack"><button class="primary" id="rcopy">Copy address</button><button class="ghost" id="rdone">Done</button></div>`;
  $('#raddr').textContent = S.address.slice(0, 32) + '\n' + S.address.slice(32);
  const draw = () => {
    let uri = 'sthir:' + S.address, msg = '';
    if (sheet.ramt.trim() !== '') {
      const u = parseUnits(sheet.ramt);
      if (u === null || u <= 0) msg = 'Enter an amount like 2.5, with up to 8 decimals. The code has no amount until you do.';
      else uri += '?amount=' + plain(u);
    }
    $('#rerr').textContent = msg;
    sheet.ruri = msg ? 'sthir:' + S.address : uri;
    try { $('#qrbox').innerHTML = qrSvg(uri); }
    catch (e) { $('#qrbox').textContent = 'Could not draw the QR code.'; }
  };
  draw();
  $('#r-amt').addEventListener('input', (e) => { sheet.ramt = e.target.value; draw(); });
  $('#rcopy').addEventListener('click', () => copy(S.address, 'Address copied'));
  $('#rsave').addEventListener('click', () => saveQr(sheet.ruri));
  $('#rshare').addEventListener('click', () => shareQr(sheet.ruri));
  $('#rdone').addEventListener('click', closeSheet);
}
async function saveQr(uri, note) {
  try {
    const url = URL.createObjectURL(await qrPng(uri));
    const a = document.createElement('a');
    a.href = url; a.download = 'sthir-qr-' + S.address.slice(0, 6) + '.png';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast(note || 'Saved. Look in your Downloads or gallery.');
  } catch (e) { toast('Could not save the picture.'); }
}
async function shareQr(uri) {
  let file;
  try { file = new File([await qrPng(uri)], 'sthir-qr.png', {type: 'image/png'}); }
  catch (e) { toast('Could not make the picture.'); return; }
  const data = {title: 'Pay me on Sthir', text: uri};
  try {
    if (navigator.canShare && navigator.canShare({files: [file]})) { await navigator.share(Object.assign({files: [file]}, data)); return; }
    if (navigator.share) { await navigator.share(data); return; }
  } catch (e) { if (e && e.name === 'AbortError') return; }
  saveQr(uri, 'Sharing is not available in this browser, so the picture was saved instead.');
}
/* ---- accounts: login screens and the Account sheet ---- */
async function api(path, body) {
  const r = await fetch(path, {method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Sthir-UI': '1'},
    body: JSON.stringify(body || {})});
  let j = {};
  try { j = await r.json(); } catch (e) {}
  if (r.status === 401) poll();
  if (!r.ok) throw new Error(j.error || 'Something went wrong.');
  return j;
}
let auth = {view: 'login', sel: '', err: '', busy: false, mode: 'text', f: {}, notice: ''};
let authShown = false, authSig = '', wasUnlocked = false, manualLogout = false;
function hideAuth() {
  if (authShown) { authShown = false; $('#auth').hidden = true; }
}
function showAuth() {
  const accts = S.accounts || [], sig = JSON.stringify([accts, S.legacy]);
  if (sheet.open) closeSheet();
  $('#auth').hidden = false;
  if (!authShown) {
    const note = wasUnlocked && !manualLogout ? 'Locked after 15 minutes without use.' : '';
    auth = {view: accts.length ? 'login' : 'signup', sel: accts.length === 1 ? accts[0].id : '',
            err: '', busy: false, mode: 'text', f: {}, notice: note};
    wasUnlocked = false; manualLogout = false;
    authShown = true; authSig = sig; drawAuth();
  } else if (sig !== authSig) { authSig = sig; drawAuth(); }
}
function authGo(view, extra) {
  auth.view = view; auth.err = ''; auth.busy = false; auth.notice = '';
  auth.f.pw = ''; auth.f.pw2 = '';
  Object.assign(auth, extra || {}); drawAuth();
}
function bindF(id, key) {
  const el = $(id); if (!el) return;
  el.addEventListener('input', (e) => { auth.f[key] = e.target.type === 'checkbox' ? e.target.checked : e.target.value; });
}
function afield(label, id, key, opts = {}) {
  const v = auth.f[key] === undefined ? (opts.def || '') : auth.f[key];
  const tag = opts.area ? `<textarea id="${id}" rows="${opts.rows || 3}" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="${esc(opts.ph || '')}">${esc(v)}</textarea>`
    : `<input id="${id}" type="${opts.type || 'text'}" autocomplete="${opts.ac || 'off'}" ${opts.max ? 'maxlength="' + opts.max + '"' : ''} spellcheck="false" autocapitalize="off" placeholder="${esc(opts.ph || '')}" value="${esc(v)}">`;
  return `<label for="${id}">${label}</label>${tag}`;
}
async function authSubmit(path, body, btn, busyText) {
  if (auth.busy) return;
  auth.busy = true; auth.err = ''; btn.disabled = true; const t = btn.textContent; btn.textContent = busyText;
  try {
    await api(path, body);
    auth.f = {};
    await poll(); setTab('wallet'); window.scrollTo(0, 0);
  } catch (e) {
    auth.busy = false; auth.err = e.message; btn.disabled = false; btn.textContent = t;
    $('#aerr').textContent = auth.err;
  }
}
function drawAuth() {
  const el = $('#authBody'), accts = S.accounts || [];
  const err = `<p class="err" id="aerr" role="alert">${esc(auth.err)}</p>`;
  const notice = auth.notice ? `<p class="banner" role="status">${esc(auth.notice)}</p>` : '';
  const head = '<div class="mark"><span class="dev" lang="hi">स्थिर</span><span class="lat">Sthir</span></div>';
  if (auth.view === 'login' && accts.length) {
    el.innerHTML = `${head}<h1>Log in</h1>${notice}
      <ul class="opts" role="group" aria-label="Profiles">${accts.map((a) =>
        `<li><button class="opt" data-id="${esc(a.id)}" aria-pressed="${a.id === auth.sel}"><span class="t">${esc(a.name)}</span></button></li>`).join('')}</ul>
      ${afield('Password', 'a-pw', 'pw', {type: 'password', ac: 'current-password'})}
      ${err}
      <button class="primary" id="alogin">Log in</button>
      <div class="alinks"><button class="link" id="agoSignup">Create a new profile</button><button class="link" id="agoImport">Use a backup or another phone</button></div>`;
    el.querySelectorAll('.opt[data-id]').forEach((b) => b.addEventListener('click', () => {
      auth.sel = b.dataset.id;
      el.querySelectorAll('.opt[data-id]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      $('#a-pw').focus();
    }));
    bindF('#a-pw', 'pw');
    const go = (e) => {
      if (!auth.sel) { $('#aerr').textContent = 'Choose a profile first.'; return; }
      authSubmit('/api/auth/login', {id: auth.sel, password: auth.f.pw || ''}, $('#alogin'), 'Unlocking…');
    };
    $('#alogin').addEventListener('click', go);
    $('#a-pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    $('#agoSignup').addEventListener('click', () => authGo('signup'));
    $('#agoImport').addEventListener('click', () => authGo('import'));
  } else if (auth.view === 'import') {
    const text = auth.mode === 'text';
    el.innerHTML = `${head}<h1>Use a backup</h1>
      <div class="seg" role="group" aria-label="Source"><button id="mText" aria-pressed="${text}">Backup text</button><button id="mRelay" aria-pressed="${!text}">Another phone</button></div>
      ${text ? `<p class="hint">Paste the backup text you saved from Account → Back up. It starts with sthir-vault: and only opens with your password.</p>
        ${afield('Backup text', 'a-bk', 'backup', {area: true, rows: 4, ph: 'sthir-vault:…'})}
        ${afield('Password', 'a-pw', 'pw', {type: 'password', ac: 'current-password'})}`
      : `<p class="hint">Log in from another phone that is on the same network, or from a public node. You need the address of the node that holds your backup, your profile name and your password.</p>
        ${afield('Node address', 'a-rl', 'relay', {ph: 'http://192.168.1.5:5001', ac: 'url'})}
        ${afield('Profile name', 'a-rn', 'rname', {ac: 'username', max: 24})}
        ${afield('Password', 'a-pw', 'pw', {type: 'password', ac: 'current-password'})}`}
      ${err}
      <button class="primary" id="aimp">${text ? 'Restore' : 'Find my profile'}</button>
      <div class="alinks"><button class="link" id="aback">${accts.length ? 'Back to log in' : 'Create a new profile'}</button></div>`;
    $('#mText').addEventListener('click', () => authGo('import', {mode: 'text'}));
    $('#mRelay').addEventListener('click', () => authGo('import', {mode: 'relay'}));
    ['#a-bk:backup', '#a-pw:pw', '#a-rl:relay', '#a-rn:rname'].forEach((p) => bindF(...p.split(':')));
    $('#aback').addEventListener('click', () => authGo(accts.length ? 'login' : 'signup'));
    $('#aimp').addEventListener('click', () => {
      if (text) authSubmit('/api/auth/import', {backup: auth.f.backup || '', password: auth.f.pw || ''}, $('#aimp'), 'Restoring…');
      else authSubmit('/api/auth/remote', {relay: auth.f.relay || '', name: auth.f.rname || '', password: auth.f.pw || ''}, $('#aimp'), 'Looking…');
    });
  } else {
    el.innerHTML = `${head}<h1>Create a profile</h1>${notice}
      <p class="hint">Your password locks the wallet key on this phone. It cannot be reset. If you lose it and have no backup, the coins are gone.</p>
      ${afield('Profile name', 'a-nm', 'name', {ac: 'username', max: 24})}
      ${afield('Password (8 or more characters)', 'a-pw', 'pw', {type: 'password', ac: 'new-password'})}
      ${afield('Repeat password', 'a-pw2', 'pw2', {type: 'password', ac: 'new-password'})}
      ${S.legacy ? `<label class="chk" for="a-ex"><input id="a-ex" type="checkbox" ${auth.f.ex === false ? '' : 'checked'}><span>Use my existing wallet from this phone<span class="note" style="display:block">Your current wallet and its saved copies get locked with this password, then the unlocked key files are deleted.</span></span></label>` : ''}
      ${err}
      <button class="primary" id="asign">Create profile</button>
      <div class="alinks">${accts.length ? '<button class="link" id="agoLogin">Log in instead</button>' : ''}<button class="link" id="agoImport">Use a backup or another phone</button></div>`;
    ['#a-nm:name', '#a-pw:pw', '#a-pw2:pw2', '#a-ex:ex'].forEach((p) => bindF(...p.split(':')));
    const go = () => {
      const nm = (auth.f.name || '').trim(), pw = auth.f.pw || '';
      let m = '';
      if (!nm) m = 'Enter a profile name.';
      else if (pw.length < 8) m = 'Use a password of at least 8 characters.';
      else if (pw !== (auth.f.pw2 || '')) m = 'The two passwords do not match.';
      if (m) { $('#aerr').textContent = m; return; }
      authSubmit('/api/auth/signup', {name: nm, password: pw, use_existing: !!S.legacy && auth.f.ex !== false}, $('#asign'), 'Creating…');
    };
    $('#asign').addEventListener('click', go);
    $('#a-pw2').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    const gl = $('#agoLogin'); if (gl) gl.addEventListener('click', () => authGo('login'));
    $('#agoImport').addEventListener('click', () => authGo('import'));
  }
}

function agoto(step, extra) {
  Object.assign(sheet, {err: '', busy: false, pw: '', pw2: '', pw3: '', conf: '', key: '', info: ''}, extra || {});
  sheet.step = step; drawSheet();
}
function abusy(btn, text) { btn.disabled = true; btn.textContent = text; sheet.busy = true; }
function afail(e) { sheet.busy = false; sheet.err = e.message; drawSheet(); }
function sfield(label, id, key, type = 'password', ac = 'current-password') {
  return `<label for="${id}">${label}</label><input id="${id}" type="${type}" autocomplete="${ac}" spellcheck="false" autocapitalize="off" value="${esc(sheet[key] || '')}">`;
}
function sbind(id, key) { const el = $(id); if (el) el.addEventListener('input', (e) => sheet[key] = e.target.value); }
function drawAccount(body) {
  const st = sheet.step, name = S && S.account ? S.account.name : '';
  const errp = `<p class="err" id="err" role="alert">${esc(sheet.err)}</p>`;
  const back = '<button class="ghost" id="aback">Back</button>';
  const menu = () => agoto('acct');
  if (st === 'acct') {
    const a = S ? S.address : '';
    body.innerHTML = `<h2 id="sheetTitle">${esc(name)}</h2>
      <p class="hint mono" style="word-break:break-all">${esc(a.slice(0, 12))}…${esc(a.slice(-6))}</p>
      <ul class="opts" style="margin-top:12px">
        ${optBtn('aBackup', 'Back up this profile', 'Save a locked copy so you can log in from another phone.')}
        ${optBtn('aKey', 'Show my key', 'The raw key. Anyone who sees it can spend your coins.')}
        ${optBtn('aPass', 'Change password', 'Lock this profile with a new password.')}
        ${optBtn('aRemove', 'Remove from this phone', 'Take this profile off the phone. Make sure you have a backup first.')}
      </ul>
      <div class="stack" style="margin-top:16px"><button class="primary" id="aOut">Log out</button><button class="ghost" id="aclose">Close</button></div>`;
    $('#aBackup').addEventListener('click', () => { agoto('abackup'); loadBackup(); });
    $('#aKey').addEventListener('click', () => agoto('akey'));
    $('#aPass').addEventListener('click', () => agoto('apass'));
    $('#aRemove').addEventListener('click', () => agoto('aremove'));
    $('#aclose').addEventListener('click', closeSheet);
    $('#aOut').addEventListener('click', async () => {
      manualLogout = true;
      try { await api('/api/auth/logout'); } catch (e) {}
      closeSheet(); await poll();
    });
  } else if (st === 'abackup') {
    const host = (sheet.relay === undefined ? (S ? S.node : '') : sheet.relay);
    const local = /^https?:\/\/(127\.0\.0\.1|localhost)/.test(host);
    body.innerHTML = `<h2 id="sheetTitle">Back up this profile</h2>
      <p class="hint">This text is your key locked with your password. It is safe to keep in notes, email or cloud storage, but it only helps if you also remember the password.</p>
      <div class="keybox" id="bkbox">${sheet.backup ? esc(sheet.backup) : 'Loading…'}</div>
      <div class="stack" style="margin-top:10px"><button class="ghost" id="bkcopy" ${sheet.backup ? '' : 'disabled'}>Copy backup text</button></div>
      ${sheet.node ? `<h2 style="font-size:17px;margin-top:24px">Keep a copy on a node</h2>
      <div class="warnbox"><p style="margin:0">Whoever runs that node can download your locked copy and try passwords on it for as long as they like. Only do this with a long, unique password (12+ characters). Your backup text above is safer.</p></div>
      <p class="hint">Then you can log in from another phone with just your name and password.${local ? ' This address only works on this phone. Use your host phone’s WiFi address, like http://192.168.1.5:5001, or a node you trust.' : ''}</p>
      <label for="s-rl">Node address</label><input id="s-rl" autocomplete="off" spellcheck="false" autocapitalize="off" value="${esc(host)}">
      ${sfield('Your password', 's-pw', 'pw')}
      <p class="${sheet.info ? 'hint' : 'err'}" id="err" role="alert">${esc(sheet.info || sheet.err)}</p>
      <div class="stack"><button class="primary" id="bksave">Save to node</button>${back}</div>` : `<div class="stack" style="margin-top:24px"><button class="ghost" id="bknode">Also keep a copy on a node (advanced)</button>${back}</div>`}`;
    $('#aback').addEventListener('click', menu);
    const c = $('#bkcopy'); if (sheet.backup) c.addEventListener('click', () => copy(sheet.backup, 'Backup copied'));
    if (!sheet.node) { $('#bknode').addEventListener('click', () => { sheet.node = true; drawSheet(); }); return; }
    sbind('#s-pw', 'pw');
    $('#s-rl').addEventListener('input', (e) => sheet.relay = e.target.value);
    $('#bksave').addEventListener('click', async (e) => {
      if (sheet.busy) return; abusy(e.target, 'Saving…');
      try { await api('/api/account/backup_online', {password: sheet.pw, relay: host}); sheet.busy = false; sheet.pw = ''; sheet.err = ''; sheet.info = 'Saved. You can now log in from another phone with this name and password.'; drawSheet(); }
      catch (x) { sheet.info = ''; afail(x); }
    });
  } else if (st === 'akey') {
    body.innerHTML = `<h2 id="sheetTitle">Show my key</h2>
      <div class="warnbox"><p style="margin:0">Anyone who sees this key can spend your coins. Do not share it or take a screenshot.</p></div>
      ${sheet.key ? `<div class="keybox" id="keybox">${esc(sheet.key)}</div>` : sfield('Your password', 's-pw', 'pw')}
      ${errp}
      <div class="stack">${sheet.key ? '<button class="primary" id="kcopy">Copy key</button>' : '<button class="primary" id="kshow">Show key</button>'}${back}</div>`;
    sbind('#s-pw', 'pw');
    $('#aback').addEventListener('click', menu);
    if (sheet.key) $('#kcopy').addEventListener('click', () => copy(sheet.key, 'Key copied'));
    else $('#kshow').addEventListener('click', async (e) => {
      if (sheet.busy) return; abusy(e.target, 'Checking…');
      try { const r = await api('/api/account/key', {password: sheet.pw}); sheet.key = r.key; sheet.pw = ''; sheet.busy = false; sheet.err = ''; drawSheet(); } catch (x) { afail(x); }
    });
  } else if (st === 'apass') {
    body.innerHTML = `<h2 id="sheetTitle">Change password</h2>
      ${sfield('Current password', 's-pw', 'pw')}${sfield('New password (8 or more characters)', 's-pw2', 'pw2', 'password', 'new-password')}${sfield('Repeat new password', 's-pw3', 'pw3', 'password', 'new-password')}
      <p class="hint">A backup you made earlier still needs the old password.</p>
      ${errp}
      <div class="stack"><button class="primary" id="pgo">Change password</button>${back}</div>`;
    sbind('#s-pw', 'pw'); sbind('#s-pw2', 'pw2'); sbind('#s-pw3', 'pw3');
    $('#aback').addEventListener('click', menu);
    $('#pgo').addEventListener('click', async (e) => {
      if (sheet.busy) return;
      if (sheet.pw2 !== sheet.pw3) { $('#err').textContent = 'The two new passwords do not match.'; return; }
      abusy(e.target, 'Changing…');
      try { await api('/api/account/password', {old: sheet.pw, new: sheet.pw2}); toast('Password changed'); agoto('acct'); } catch (x) { afail(x); }
    });
  } else if (st === 'aremove') {
    body.innerHTML = `<h2 id="sheetTitle">Remove from this phone</h2>
      <div class="warnbox"><p style="margin:0">This takes <strong>${esc(name)}</strong> off this phone. The coins stay on the chain at the same address. Without a backup and the password you cannot get them back.</p></div>
      ${sfield('Your password', 's-pw', 'pw')}
      <label for="s-cf">Type DELETE to confirm</label><input id="s-cf" autocomplete="off" autocapitalize="characters" spellcheck="false" value="${esc(sheet.conf || '')}">
      ${errp}
      <div class="stack"><button class="primary" id="rgo">Remove profile</button>${back}</div>`;
    sbind('#s-pw', 'pw'); sbind('#s-cf', 'conf');
    $('#aback').addEventListener('click', menu);
    $('#rgo').addEventListener('click', async (e) => {
      if (sheet.busy) return;
      if ((sheet.conf || '').trim() !== 'DELETE') { $('#err').textContent = 'Type DELETE in capital letters to continue.'; return; }
      abusy(e.target, 'Removing…');
      try { manualLogout = true; await api('/api/account/remove', {password: sheet.pw, confirm: 'DELETE'}); closeSheet(); await poll(); }
      catch (x) { manualLogout = false; afail(x); }
    });
  }
}
function optBtn(id, t, s) { return `<li><button class="opt" id="${id}"><span class="t">${t}</span><span class="s">${s}</span></button></li>`; }
async function loadBackup() {
  try {
    const r = await api('/api/account/export');
    if (sheet.open && sheet.step === 'abackup') { sheet.backup = r.backup; drawSheet(); }
  } catch (e) { if (sheet.step === 'abackup') { sheet.err = e.message; drawSheet(); } }
}
async function doSend() {
  if (sheet.sending) return;
  sheet.sending = true; sheet.err = '';
  const btn = $('#confirm'); btn.disabled = true; btn.textContent = 'Sending…';
  try {
    const r = await fetch('/api/send', {method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Sthir-UI': '1'},
      body: JSON.stringify({to: sheet.to, amount: sheet.amt.trim(), fee: sheet.fee.trim()})});
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || 'The payment was not sent.');
    sheet.step = 'done'; sheet.txid = j.txid; sheet.sending = false; drawSheet();
    toast('Sent'); poll();
  } catch (e) {
    sheet.err = e.message; sheet.sending = false; drawSheet();
  }
}
function openSheet(step = 'form') {
  sheet = {open:true, step, to:'', amt:'', fee:'0.001', err:'', sending:false, txid:'', ramt:''};
  drawSheet();
  $('#scrim').classList.add('open'); $('#sheet').classList.add('open');
  if (step === 'scan') runScan();
  else if (step === 'form') setTimeout(() => { const f = $('#f-to'); if (f) f.focus(); }, 260);
}
function closeSheet() {
  stopScan();
  sheet.open = false; sheet.key = '';
  $('#scrim').classList.remove('open'); $('#sheet').classList.remove('open');
  $('#openSend').focus();
}
$('#openSend').addEventListener('click', () => openSheet('form'));
$('#openReceive').addEventListener('click', () => openSheet('receive'));
$('#moScan').addEventListener('click', () => openSheet('scan'));
$('#moReq').addEventListener('click', () => openSheet('receive'));
$('#moWallet').addEventListener('click', () => openSheet('acct'));
$('#scrim').addEventListener('click', closeSheet);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && sheet.open) closeSheet(); });

async function poll() {
  try {
    const r = await fetch('/api/state', {cache: 'no-store'});
    S = await r.json();
  } catch (e) {
    S = Object.assign({node: '', address: '', key: '', node_ok: false}, S || {}, {ui_down: true});
  }
  render();
}
let lastPing = 0;
['pointerdown', 'keydown'].forEach((ev) => document.addEventListener(ev, () => {
  if (S && !S.locked && Date.now() - lastPing > 30000) {
    lastPing = Date.now();
    fetch('/api/auth/ping', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Sthir-UI': '1'}, body: '{}'}).catch(() => {});
  }
}, {passive: true}));
poll(); setInterval(poll, 3000);
})();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(prog="sthir_ui")
    ap.add_argument("--node", default="http://127.0.0.1:5001",
                    help="node to talk to (default %(default)s)")
    ap.add_argument("--key", default="wallet.key", help="wallet key file")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    ui = UIState(a.node, a.key)
    server = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(ui, a.port))
    server.daemon_threads = True
    n = len(ui.store.listing())
    print(f"Sthir wallet on node {ui.node}: {n} profile{'s' if n != 1 else ''} on this phone")
    print(f"Open this in your phone's browser: http://127.0.0.1:{a.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    main()
