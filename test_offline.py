import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

import sthir_offline as O
import sthir_verify as V
from sthir import UNIT, Wallet


class Clock:
    def __init__(self): self.t = 1_800_000_000.0
    def __call__(self): return self.t


class VoucherTests(unittest.TestCase):
    def setUp(self):
        self.c = Clock()
        self.hub = O.Hub(now=self.c)
        self.a, self.r1, self.r2 = Wallet(), Wallet(), Wallet()
        self.hub.credit(self.a.address, 1000 * UNIT)
        self.att = self.hub.lock_book(O.lock_request(self.a, 10, 20 * UNIT, int(self.c.t) + 86400))
        self.book = self.att["book"]
        self.shop = O.Receiver(self.r1.address, self.hub.address, 50 * UNIT, now=self.c)

    def v(self, n, to=None, w=None):
        return O.issue_voucher(w or self.a, self.book, n, (to or self.r1).address, self.c.t)

    def test_lock_takes_vouchers_plus_bond(self):
        self.assertEqual(self.hub.balance(self.a.address), (1000 - 200 - 50) * UNIT)

    def test_lock_needs_funds_signature_and_sane_expiry(self):
        poor = Wallet()
        with self.assertRaises(O.HubError):
            self.hub.lock_book(O.lock_request(poor, 1, UNIT, int(self.c.t) + 3600))
        req = O.lock_request(self.a, 1, UNIT, int(self.c.t) + 3600)
        req["value"] = 2 * UNIT
        with self.assertRaises(O.HubError):
            self.hub.lock_book(req)                       # signature no longer matches
        for exp in (int(self.c.t) + 5, int(self.c.t) + 40 * 86400):
            with self.assertRaises(O.HubError):
                self.hub.lock_book(O.lock_request(self.a, 1, UNIT, exp))
        ok = O.lock_request(self.a, 1, UNIT, int(self.c.t) + 3600)
        self.hub.lock_book(ok)
        with self.assertRaises(O.HubError):
            self.hub.lock_book(ok)                        # replay

    def test_receiver_checks(self):
        self.assertEqual(self.shop.accept(self.v(1), self.att), (True, "ok"))
        self.assertFalse(self.shop.accept(self.v(1), self.att)[0])                # seen
        self.assertFalse(self.shop.accept(self.v(99), self.att)[0])               # outside book
        self.assertFalse(self.shop.accept(self.v(2, to=self.r2), self.att)[0])    # for someone else
        self.assertFalse(self.shop.accept(self.v(3, w=Wallet()), self.att)[0])    # wrong signer
        forged = dict(self.att, hub_sig=Wallet().sign(O.canon(self.book)))
        self.assertFalse(self.shop.accept(self.v(4), forged)[0])                  # not our hub
        small = O.Receiver(self.r1.address, self.hub.address, 10 * UNIT, now=self.c)
        self.assertFalse(small.accept(self.v(5), self.att)[0])                    # over the limit
        self.c.t += 2 * 86400
        self.assertFalse(self.shop.accept(self.v(6), self.att)[0])                # expired

    def test_pays_once_and_is_idempotent(self):
        v = self.v(2)
        self.assertEqual(self.hub.redeem(v)["status"], "paid")
        self.assertEqual(self.hub.redeem(v)["status"], "already_redeemed")
        self.assertEqual(self.hub.balance(self.r1.address), 20 * UNIT)

    def test_status_tells_sender_whether_it_was_paid(self):
        self.assertEqual(self.hub.voucher_status(self.book["id"], 3, self.r1.address)["state"], "UNUSED")
        self.hub.redeem(self.v(3))
        st = self.hub.voucher_status(self.book["id"], 3, self.r1.address)
        self.assertEqual((st["state"], st["paid_to_you"]), ("PAID", True))
        self.assertFalse(self.hub.voucher_status(self.book["id"], 3, self.r2.address)["paid_to_you"])
        self.assertNotIn("to", self.hub.voucher_status(self.book["id"], 3))        # never lists the receiver
        with self.assertRaises(O.HubError):
            self.hub.voucher_status(self.book["id"], 99)
        with self.assertRaises(O.HubError):
            self.hub.voucher_status("nope", 1)

    def test_double_spend_is_slashed_and_banned(self):
        self.hub.redeem(self.v(7))
        r = self.hub.redeem(self.v(7, to=self.r2))
        self.assertEqual(r["status"], "fraud_detected")
        self.assertEqual(r["shortfall"], 0)
        self.assertEqual(self.hub.balance(self.r2.address), 20 * UNIT)
        self.assertIn(self.a.address, self.hub.s["banned"])
        with self.assertRaises(O.HubError):
            self.hub.lock_book(O.lock_request(self.a, 1, UNIT, int(self.c.t) + 3600))

    def test_total_paid_never_exceeds_locked(self):
        paid = 0
        for n in range(10):                                  # every number spent twice
            for who in (self.r1, self.r2):
                r = self.hub.redeem(self.v(n, to=who))
                paid += r.get("amount", r.get("paid", 0))
        self.assertLessEqual(paid, 200 * UNIT + 50 * UNIT)
        self.assertGreater(sum(r["shortfall"] for r in self.hub.s["books"].values()), 0)   # someone lost out
        self.assertGreaterEqual(self.hub.s["books"][self.book["id"]]["remaining"], 0)

    def test_close_after_grace_returns_remainder_and_blocks_late_redeem(self):
        self.hub.redeem(self.v(1))
        with self.assertRaises(O.HubError):
            self.hub.close(self.book["id"])
        self.c.t += 86400 + O.SETTLE_GRACE + 1
        self.assertEqual(self.hub.close(self.book["id"])["returned"], (180 + 50) * UNIT)
        self.assertEqual(self.hub.redeem(self.v(2))["status"], "rejected")
        self.assertEqual(self.hub.close(self.book["id"])["returned"], 0)

    def test_persistence(self):
        import os, tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "h.json")
        h = O.Hub(p, now=self.c)
        h.credit(self.a.address, 100 * UNIT)
        h2 = O.Hub(p, now=self.c)
        self.assertEqual(h2.balance(self.a.address), 100 * UNIT)

    def test_lattice_scheme_is_honest_when_missing(self):
        try:
            import oqs  # noqa
            self.skipTest("oqs installed")
        except ImportError:
            with self.assertRaises(O.SchemeUnavailable):
                O.sig_verify("ml-dsa-65", "00", b"x", "00")


class RelayTests(unittest.TestCase):
    def test_put_get_ack_expire_limits(self):
        c = Clock(); r = O.Relay(now=c)
        box = __import__("hashlib").sha256(b"tok").hexdigest()
        import base64
        blob = base64.b64encode(b"ciphertext").decode()
        r.put(box, blob, 100)
        got = r.get("tok")["messages"]
        self.assertEqual(len(got), 1)
        self.assertEqual(r.get("wrong")["messages"], [])
        r.get("tok", ack=[got[0]["id"]])
        self.assertEqual(r.get("tok")["messages"], [])
        r.put(box, blob, 100); c.t += 200
        self.assertEqual(r.get("tok")["messages"], [])
        with self.assertRaises(O.HubError):
            r.put(box, base64.b64encode(b"x" * 70000).decode())
        with self.assertRaises(O.HubError):
            r.put("zz", blob)
        with self.assertRaises(O.HubError):
            r.put(box, "not base64!")


class VerifyTests(unittest.TestCase):
    N, K = 256, 12

    def test_honest_passes_cheaply(self):
        p = V.Prover(b"s", self.N)
        r = V.verify_samples(p.claim(), V.sample_openings(p, self.K), self.K)
        self.assertTrue(r["ok"])
        self.assertEqual(r["cost"]["steps_rerun"], self.K)

    def test_start_and_end_lies_are_caught_directly(self):
        p = V.Prover(b"s", self.N)
        cl, op = p.claim(), V.sample_openings(p, self.K)
        self.assertFalse(V.verify_samples(dict(cl, final="00" * 32), op, self.K)["ok"])
        bad = dict(op, first=dict(op["first"], state="00" * 32))
        self.assertFalse(V.verify_samples(cl, bad, self.K)["ok"])
        op2 = V.sample_openings(p, self.K)
        op2["pairs"][0][1]["state"] = op2["pairs"][0][0]["state"]
        self.assertFalse(V.verify_samples(cl, op2, self.K)["ok"])
        self.assertFalse(V.verify_samples(cl, {}, self.K)["ok"])

    def test_wide_cheat_is_caught_and_one_step_cheat_needs_dispute(self):
        honest = V.Prover(b"s", self.N)
        for j in range(0, self.N, 17):
            cheat = V.Prover(b"s", self.N, cheat_at=j)
            d = V.bisect(cheat, honest)
            ref = V.referee(cheat.claim(), d["lo"], d["hi"])
            self.assertTrue(ref["fraud_proven"])
            self.assertEqual(ref["step"], j)
            self.assertLessEqual(d["rounds"], 8)

    def test_false_challenge_fails(self):
        p = V.Prover(b"s", self.N)
        self.assertFalse(V.referee(p.claim(), p.open(5), p.open(6))["fraud_proven"])
        self.assertFalse(V.referee(p.claim(), p.open(5), p.open(7))["fraud_proven"])
        forged = p.open(6); forged["state"] = p.open(9)["state"]
        self.assertFalse(V.referee(p.claim(), p.open(5), forged)["fraud_proven"])

    def test_merkle_paths_for_odd_sizes(self):
        for n in (2, 3, 5, 6, 7, 100):
            p = V.Prover(b"odd", n)
            for i in range(n + 1):
                self.assertIsNotNone(V._opened(p.claim(), p.open(i)))


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.hub = O.Hub()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), O.make_handler(O.make_router(self.hub, O.Relay(), True)))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def post(self, path, body, ctype="application/json"):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(), {"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_end_to_end_over_http(self):
        a, r1 = Wallet(), Wallet()
        self.assertEqual(self.post("/admin/credit", {"address": a.address, "amount": 500 * UNIT})[0], 200)
        import time
        s, att = self.post("/voucher/lock", O.lock_request(a, 5, 10 * UNIT, int(time.time()) + 3600))
        self.assertEqual(s, 200)
        v = O.issue_voucher(a, att["book"], 1, r1.address)
        s, r = self.post("/voucher/check", {"voucher": v, "attested": att, "receiver": r1.address, "cap": 20 * UNIT})
        self.assertTrue(r["ok"])
        self.assertEqual(self.post("/voucher/redeem", v)[1]["status"], "paid")
        s, st = self.post("/voucher/status", {"book": att["book"]["id"], "n": 1, "to": r1.address})
        self.assertEqual((st["state"], st["paid_to_you"]), ("PAID", True))
        self.assertEqual(self.post("/voucher/status", {"book": att["book"]["id"], "n": "x"})[0], 400)
        p = V.Prover(b"h", 64)
        s, r = self.post("/verify/samples", {"claim": p.claim(), "openings": V.sample_openings(p, 8), "k": 8})
        self.assertTrue(r["ok"])

    def test_guards(self):
        self.assertEqual(self.post("/voucher/redeem", {}, "text/plain")[0], 415)
        self.assertEqual(self.post("/voucher/redeem", {})[0], 400)
        self.assertEqual(self.post("/nope", {})[0], 404)
        self.assertEqual(self.post("/voucher/lock", {"junk": 1})[0], 400)
        s, _ = self.post("/verify/samples", {"claim": 5, "openings": 5})
        self.assertIn(s, (200, 400))


if __name__ == "__main__":
    unittest.main()
