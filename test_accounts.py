import http.client
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import sthir_auth as A
from sthir_net import NetNode
from sthir import Params
from sthir_ui import UIState, make_handler, IDLE_SECONDS
import sthir_net

PW = "correct horse"


class FakeNode:
    """Answers /status /account /peers /chain /miner and the /vault relay."""

    def __init__(self, miner=None):
        self.miner, self.vaults = miner, {}
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _j(self, obj, code=200):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                if self.path == "/status":
                    self._j({"tip": "t", "height": 0, "miner": outer.miner})
                elif self.path.startswith("/account/"):
                    self._j({"balance": 0, "nonce": 0, "next_nonce": 0})
                elif self.path == "/peers":
                    self._j({"peers": []})
                elif self.path == "/chain":
                    self._j([])
                elif self.path.startswith("/vault/"):
                    v = outer.vaults.get(self.path.split("/")[2])
                    self._j({"blob": v} if v else {"error": "nf"}, 200 if v else 404)
                else:
                    self._j({}, 404)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                if self.path == "/miner" and self.headers.get("X-Sthir-UI") == "1":
                    outer.miner = body["address"]
                    self._j({"miner": outer.miner})
                elif self.path.startswith("/vault/"):
                    outer.vaults[self.path.split("/")[2]] = body["blob"]
                    self._j({"saved": True})
                else:
                    self._j({"error": "no"}, 403)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class VaultTests(unittest.TestCase):
    def test_round_trip_and_wrong_password(self):
        k = A.new_key_hex()
        v = A.seal(k, PW)
        self.assertEqual(A.open_vault(v, PW), k)
        with self.assertRaises(A.BadPassword):
            A.open_vault(v, PW + "x")

    def test_key_is_not_visible_in_vault(self):
        k = A.new_key_hex()
        self.assertNotIn(k, json.dumps(A.seal(k, PW)))

    def test_tampered_vault_rejected(self):
        v = A.seal(A.new_key_hex(), PW)
        v["ct"] = ("00" if v["ct"][:2] != "00" else "11") + v["ct"][2:]
        with self.assertRaises(A.BadPassword):
            A.open_vault(v, PW)

    def test_hostile_kdf_parameters_refused(self):
        v = A.seal(A.new_key_hex(), PW)
        for bad in ({"n": 2 ** 30}, {"r": 64}, {"p": 99}, {"n": 3}, {"v": 2}, {"salt": "00"}):
            with self.assertRaises(ValueError):
                A.open_vault(dict(v, **bad), PW)
        with self.assertRaises(ValueError):
            A.open_vault("junk", PW)

    def test_password_rules(self):
        with self.assertRaises(ValueError):
            A.seal(A.new_key_hex(), "short")

    def test_export_round_trip_survives_line_wrapping(self):
        v = A.seal(A.new_key_hex(), PW)
        s = A.make_export("Ravi", "a" * 64, v)
        wrapped = "\n".join(s[i:i + 40] for i in range(0, len(s), 40))
        self.assertEqual(A.parse_export(wrapped)["vault"], v)
        for bad in ("", "hello", s[:-10], "sthir-vault:!!!!"):
            with self.assertRaises(ValueError):
                A.parse_export(bad)

    def test_throttle_doubles_and_resets(self):
        t = [0.0]
        th = A.Throttle(free=3, base=10, cap=40, clock=lambda: t[0])
        for _ in range(2):
            th.fail("a")
        th.check("a")
        th.fail("a")
        with self.assertRaises(A.Locked):
            th.check("a")
        t[0] = 11
        th.check("a")
        th.fail("a")  # 4th: wait 20
        t[0] = 25
        with self.assertRaises(A.Locked):
            th.check("a")
        th.ok("a")
        th.check("a")
        th.check("other")


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.key = os.path.join(self.dir, "wallet.key")
        self.fake = FakeNode()
        self.ui = UIState(self.fake.url, self.key)

    def tearDown(self):
        self.fake.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def write_legacy(self, path, key=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        key = key or A.new_key_hex()
        with open(path, "w") as f:
            f.write(key)
        return key


class AccountFlowTests(Base):
    def test_signup_login_logout(self):
        r = self.ui.signup("Ravi", PW)
        tok = r["_token"]
        self.assertTrue(self.ui.authed(tok))
        self.assertEqual(self.ui.state(tok)["account"]["name"], "Ravi")
        self.ui.logout()
        self.assertFalse(self.ui.authed(tok))
        st = self.ui.state(tok)
        self.assertTrue(st["locked"])
        self.assertNotIn("address", st)
        acct_id = self.ui.store.listing()[0]["id"]
        t2 = self.ui.login(acct_id, PW)["_token"]
        self.assertTrue(self.ui.authed(t2))
        self.assertFalse(self.ui.authed(tok))   # old token stays dead

    def test_wrong_password_rejected_and_throttled(self):
        self.ui.signup("Ravi", PW)
        self.ui.logout()
        acct_id = self.ui.store.listing()[0]["id"]
        for _ in range(5):
            with self.assertRaises(A.BadPassword):
                self.ui.login(acct_id, "nope nope nope")
        with self.assertRaises(A.Locked):
            self.ui.login(acct_id, PW)   # even the right password waits

    def test_duplicate_name_and_weak_password(self):
        self.ui.signup("Ravi", PW)
        with self.assertRaises(ValueError):
            self.ui.signup("ravi", PW)
        with self.assertRaises(ValueError):
            self.ui.signup("Sita", "abc")

    def test_two_profiles_have_different_wallets(self):
        a = self.ui.signup("Ravi", PW)["address"]
        b = self.ui.signup("Sita", "another pass")["address"]
        self.assertNotEqual(a, b)
        self.assertEqual({x["name"] for x in self.ui.store.listing()}, {"Ravi", "Sita"})

    def test_idle_lock(self):
        tok = self.ui.signup("Ravi", PW)["_token"]
        self.ui.sess["last"] -= IDLE_SECONDS + 5
        self.assertFalse(self.ui.authed(tok))
        self.assertTrue(self.ui.state(tok)["locked"])

    def test_accounts_file_has_no_plaintext_key(self):
        self.ui.signup("Ravi", PW)
        priv = self.ui.sess["wallet"]._sk.private_bytes_raw().hex()
        self.assertEqual(len(priv), 64)
        path = os.path.join(self.dir, "accounts.json")
        with open(path) as f:
            self.assertNotIn(priv, f.read())
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)

    def test_sensitive_actions_need_password_again(self):
        self.ui.signup("Ravi", PW)
        with self.assertRaises(A.BadPassword):
            self.ui.show_key("wrong password")
        self.assertEqual(len(self.ui.show_key(PW)["key"]), 64)

    def test_change_password(self):
        self.ui.signup("Ravi", PW)
        with self.assertRaises(A.BadPassword):
            self.ui.change_password("wrong password", "new password1")
        self.ui.change_password(PW, "new password1")
        self.ui.logout()
        acct_id = self.ui.store.listing()[0]["id"]
        with self.assertRaises(A.BadPassword):
            self.ui.login(acct_id, PW)
        self.ui.login(acct_id, "new password1")

    def test_remove_keeps_sealed_copy(self):
        self.ui.signup("Ravi", PW)
        with self.assertRaises(ValueError):
            self.ui.remove_account(PW, "yes")
        self.ui.remove_account(PW, "DELETE")
        self.assertEqual(self.ui.store.listing(), [])
        removed = open(os.path.join(self.dir, "accounts.json.removed")).read()
        self.assertIn("Ravi", removed)
        self.assertFalse(self.ui.authed(None))

    def test_send_requires_session(self):
        with self.assertRaises(PermissionError):
            self.ui.send("a" * 64, "1", "0")


class MigrationTests(Base):
    def test_old_plaintext_keys_become_sealed_accounts_then_are_removed(self):
        k1 = self.write_legacy(self.key)
        k2 = self.write_legacy(os.path.join(self.dir, "wallet-backups", "1700000000-aaaaaaaaaaaa.key"))
        addr1 = A.wallet_from_hex(k1).address
        self.assertTrue(self.ui.locked_state()["legacy"])
        r = self.ui.signup("Ravi", PW, use_existing=True)
        self.assertEqual(r["address"], addr1)       # the active wallet stays the active one
        self.assertEqual(r["migrated"], 2)
        self.assertFalse(os.path.exists(self.key))
        self.assertEqual(os.listdir(os.path.join(self.dir, "wallet-backups")), [])
        names = {a["name"] for a in self.ui.store.listing()}
        self.assertEqual(len(names), 2)
        # both sealed keys open with the same password
        for a in self.ui.store.accounts:
            A.open_vault(a["vault"], PW)
        self.assertFalse(self.ui.locked_state()["legacy"])

    def test_without_use_existing_old_keys_are_left_alone(self):
        self.write_legacy(self.key)
        self.ui.signup("Ravi", PW, use_existing=False)
        self.assertTrue(os.path.exists(self.key))

    def test_failed_migration_removes_nothing(self):
        self.write_legacy(self.key)
        orig = A.open_vault
        A.open_vault = lambda v, p: "0" * 64
        try:
            with self.assertRaises(Exception):
                A.migrate_legacy(self.ui.store, A.legacy_keys(self.key, ""), PW, "Ravi")
        finally:
            A.open_vault = orig
        self.assertTrue(os.path.exists(self.key))


class BackupTests(Base):
    def test_export_and_import_on_another_phone(self):
        r = self.ui.signup("Ravi", PW)
        text = self.ui.export_backup()["backup"]
        d2 = tempfile.mkdtemp()
        try:
            other = UIState(self.fake.url, os.path.join(d2, "wallet.key"))
            with self.assertRaises(A.BadPassword):
                other.import_backup(text, "wrong password")
            r2 = other.import_backup(text, PW)
            self.assertEqual(r2["address"], r["address"])
            with self.assertRaises(ValueError):    # same wallet twice
                other.import_backup(text, PW, "Copy")
        finally:
            shutil.rmtree(d2, ignore_errors=True)

    def test_online_backup_and_login_from_elsewhere(self):
        r = self.ui.signup("Ravi", PW)
        with self.assertRaises(A.BadPassword):
            self.ui.backup_online("wrong password", self.fake.url)
        with self.assertRaises(ValueError):
            short = self.ui.change_password(PW, "elevenchars")  # 11 chars is a valid password...
            self.ui.backup_online("elevenchars", self.fake.url)  # ...but too short for a node copy
        self.ui.change_password("elevenchars", PW)
        self.ui.backup_online(PW, self.fake.url)
        # the relay holds only sealed text
        stored = list(self.fake.vaults.values())
        self.assertEqual(len(stored), 1)
        self.assertNotIn("Ravi" + PW, stored[0])
        d2 = tempfile.mkdtemp()
        try:
            other = UIState(self.fake.url, os.path.join(d2, "wallet.key"))
            with self.assertRaises(ValueError):
                other.remote_login(self.fake.url, "Ravi", "wrong password")   # no backup under that id
            r2 = other.remote_login(self.fake.url, "Ravi", PW)
            self.assertEqual(r2["address"], r["address"])
        finally:
            shutil.rmtree(d2, ignore_errors=True)

    def test_relay_address_must_be_http(self):
        self.ui.signup("Ravi", PW)
        for bad in ("file:///etc/passwd", "ftp://x", "javascript:1", "", "http://a b"):
            with self.assertRaises(ValueError):
                self.ui.backup_online(PW, bad)


class MinerFollowTests(Base):
    def test_node_waiting_for_a_wallet_starts_paying_the_first_login(self):
        r = self.ui.signup("Ravi", PW)
        self.assertEqual(self.fake.miner, r["address"])
        self.assertEqual(open(os.path.join(self.dir, "miner.addr")).read(), r["address"])

    def test_follows_between_own_accounts_but_not_a_stranger(self):
        a = self.ui.signup("Ravi", PW)["address"]
        b = self.ui.signup("Sita", "another pass")["address"]
        self.assertEqual(self.fake.miner, b)
        self.fake.miner = "f" * 64          # someone else's miner address
        self.ui.logout()
        self.ui.login(self.ui.store.by_name("Ravi")["id"], PW)
        self.assertEqual(self.fake.miner, "f" * 64)


class HandlerTests(Base):
    def setUp(self):
        super().setUp()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        self.port = self.srv.server_address[1]
        self.srv.RequestHandlerClass = make_handler(self.ui, self.port)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def req(self, method, path, body=None, headers=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        h = {"Content-Type": "application/json", "X-Sthir-UI": "1",
             "Host": f"127.0.0.1:{self.port}"}
        h.update(headers or {})
        if cookie:
            h["Cookie"] = cookie
        h = {k: v for k, v in h.items() if v is not None}
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        return r.status, data, r.getheader("Set-Cookie")

    def test_cookie_login_flow_and_flags(self):
        code, body, cookie = self.req("POST", "/api/auth/signup", {"name": "Ravi", "password": PW})
        self.assertEqual(code, 200)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn("_token", json.loads(body))
        ck = cookie.split(";")[0]
        code, body, _ = self.req("GET", "/api/state", cookie=ck)
        self.assertFalse(json.loads(body)["locked"])
        code, _, clear = self.req("POST", "/api/auth/logout", cookie=ck)
        self.assertIn("Max-Age=0", clear)
        self.assertTrue(json.loads(self.req("GET", "/api/state", cookie=ck)[1])["locked"])

    def test_private_routes_need_the_cookie(self):
        for path in ("/api/send", "/api/account/key", "/api/account/export", "/api/account/remove"):
            self.assertEqual(self.req("POST", path, {})[0], 401, path)
        self.ui.signup("Ravi", PW)
        self.assertEqual(self.req("POST", "/api/account/key", {"password": PW}, cookie="sthir_session=forged")[0], 401)

    def test_locked_state_leaks_no_wallet_data(self):
        self.ui.signup("Ravi", PW)
        self.ui.logout()
        st = json.loads(self.req("GET", "/api/state")[1])
        self.assertEqual(set(st), {"locked", "accounts", "node", "legacy"})
        self.assertEqual(list(st["accounts"][0]), ["id", "name"])

    def test_csrf_guards_still_apply(self):
        self.assertEqual(self.req("POST", "/api/auth/login", {}, headers={"X-Sthir-UI": None})[0], 403)
        self.assertEqual(self.req("POST", "/api/auth/login", {}, headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/auth/login", {}, headers={"Host": "evil.example"})[0], 403)

    def test_errors_do_not_crash_and_wrong_password_is_403(self):
        self.ui.signup("Ravi", PW)
        self.ui.logout()
        acct_id = self.ui.store.listing()[0]["id"]
        self.assertEqual(self.req("POST", "/api/auth/login", {"id": acct_id, "password": "bad bad bad"})[0], 403)
        self.assertEqual(self.req("POST", "/api/auth/login", {"id": 5, "password": 5})[0], 400)
        self.assertEqual(self.req("POST", "/api/auth/signup", {"name": "", "password": PW})[0], 400)


class NodeRelayTests(unittest.TestCase):
    def setUp(self):
        self.nn = NetNode(Params(blocks_per_year=100, difficulty_bits=6), "http://x", None)
        self.vid = "ab" * 32
        self.blob = "sthir-vault:" + "A" * 200

    def test_mining_switch(self):
        with self.assertRaises(ValueError):
            self.nn.set_mining(True)           # no wallet address yet
        self.nn.mine_later = True
        self.nn.set_miner("ab" * 32)           # login sets the address; thread idles on the switch
        self.nn.set_mining(False)
        self.assertFalse(self.nn.mining)
        self.nn.set_mining(True)
        self.assertTrue(self.nn.mining)
        self.nn.stop.set()

    def test_store_and_fetch(self):
        self.assertIsNone(self.nn.vault_get(self.vid))
        self.nn.vault_put(self.vid, self.blob)
        self.assertEqual(self.nn.vault_get(self.vid), self.blob)

    def test_rejects_junk(self):
        for vid, blob in (("zz", self.blob), (self.vid, "hello"), (self.vid, "sthir-vault:" + "A" * 5000),
                          (self.vid, 5), ("../../etc/passwd", self.blob)):
            with self.assertRaises(ValueError):
                self.nn.vault_put(vid, blob)
        with self.assertRaises(ValueError):
            self.nn.vault_get("../../etc/passwd")

    def test_persists_in_vault_dir(self):
        d = tempfile.mkdtemp()
        try:
            self.nn.vault_dir = os.path.join(d, "vaults")
            self.nn.vault_put(self.vid, self.blob)
            fresh = NetNode(Params(blocks_per_year=100, difficulty_bits=6), "http://x", None)
            fresh.vault_dir = self.nn.vault_dir
            self.assertEqual(fresh.vault_get(self.vid), self.blob)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_rate_limit(self):
        ok = [self.nn._vault_rate_ok("1.2.3.4") for _ in range(25)]
        self.assertEqual(ok.count(True), 20)

    def test_mine_later_only_when_enabled(self):
        with self.assertRaises(ValueError):
            self.nn.set_miner("a" * 64)
        self.nn.mine_later = True
        self.nn.miner_started = True   # don't spin up a real miner thread in the test
        self.assertEqual(self.nn.set_miner("A" * 64), "a" * 64)


if __name__ == "__main__":
    unittest.main()
