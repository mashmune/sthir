import copy
import unittest

import sthir_zk as Z


class CurveTests(unittest.TestCase):
    def test_group_basics(self):
        self.assertTrue(Z.eq(Z.mul(Z.L, Z.G, reduce=False), Z.ZERO))
        self.assertTrue(Z.eq(Z.mul(Z.L, Z.H, reduce=False), Z.ZERO))
        self.assertTrue(Z.eq(Z.add(Z.G, Z.G), Z.mul(2, Z.G)))
        self.assertTrue(Z.eq(Z.add(Z.mul(5, Z.G), Z.neg(Z.mul(5, Z.G))), Z.ZERO))
        self.assertTrue(Z.eq(Z.decompress(Z.compress(Z.H)), Z.H))
        self.assertFalse(Z.eq(Z.G, Z.H))
        self.assertTrue(Z.eq(Z._G.mul(12345), Z.mul(12345, Z.G)))

    def test_bad_points_rejected(self):
        order2 = (Z.p - 1).to_bytes(32, "little")             # (0, -1): a point of order 2
        for bad in (order2, b"\x00" * 31, b"\xff" * 32):
            with self.assertRaises(ValueError):
                Z.decompress(bad)


class ProofTests(unittest.TestCase):
    def test_range_proof_complete_and_binding(self):
        for v in (0, 1, 2 ** 32 - 1, 123456):
            r = Z.rand_scalar()
            C = Z.commit(v, r)
            self.assertTrue(Z.range_verify(C, Z.range_prove(v, r)))
        r = Z.rand_scalar()
        proof = Z.range_prove(7, r)
        self.assertFalse(Z.range_verify(Z.commit(8, r), proof))             # proof does not move to another amount
        self.assertFalse(Z.range_verify(Z.commit(7, r), proof, b"other"))   # nor to another context

    def test_out_of_range_cannot_be_proven(self):
        for v in (-1, 2 ** 32, Z.L - 5):
            with self.assertRaises(ValueError):
                Z.range_prove(v, Z.rand_scalar())

    def test_bit_proof_rejects_a_non_bit(self):
        r = Z.rand_scalar()
        C = Z.commit(2, r)                                   # holds 2, not 0 or 1
        for bit in (0, 1):
            self.assertFalse(Z._bit_verify(C, Z._bit_prove(bit, r, C, b"x"), b"x"))
        C1 = Z.commit(1, r)
        self.assertTrue(Z._bit_verify(C1, Z._bit_prove(1, r, C1, b"x"), b"x"))

    def test_hiding(self):
        self.assertNotEqual(Z.compress(Z.commit(5, Z.rand_scalar())), Z.compress(Z.commit(5, Z.rand_scalar())))


class TxTests(unittest.TestCase):
    def test_valid_transactions(self):
        inp = [(70, Z.rand_scalar()), (30, Z.rand_scalar())]
        tx, op = Z.build_tx(inp, [60, 39], 1)
        self.assertEqual(Z.verify_tx(tx), (True, "ok"))
        for (v, r), o in zip(op, tx["outputs"]):
            self.assertTrue(Z.open_note(o["C"], v, r))
            self.assertFalse(Z.open_note(o["C"], v + 1, r))

    def test_cannot_create_coins(self):
        inp = [(100, Z.rand_scalar())]
        with self.assertRaises(ValueError):
            Z.build_tx(inp, [60, 60], 0)
        # a cheater skips the honest builder and signs the books with the true excess anyway
        out_v, out_r = [60, 60], [Z.rand_scalar(), Z.rand_scalar()]
        cin = [Z.compress(Z.commit(*inp[0])).hex()]
        cout = [Z.compress(Z.commit(v, r)).hex() for v, r in zip(out_v, out_r)]
        ctx = Z._tx_ctx(cin, cout, 0)
        tx = {"inputs": cin, "fee": 0,
              "outputs": [{"C": c, "range": Z.range_prove(v, r, ctx + bytes([i]))}
                          for i, (c, v, r) in enumerate(zip(cout, out_v, out_r))],
              "balance": Z._balance_prove((inp[0][1] - sum(out_r)) % Z.L, Z._excess_point(cin, cout, 0), ctx)}
        ok, why = Z.verify_tx(tx)
        self.assertFalse(ok)
        self.assertIn("equal", why)

    def test_negative_output_trick_fails(self):
        # Try to pay out 150 and "-50" (as L-50) from 100: balances mod L, but no range proof exists.
        inp = [(100, Z.rand_scalar())]
        out_v, out_r = [150, Z.L - 50], [Z.rand_scalar(), Z.rand_scalar()]
        cin = [Z.compress(Z.commit(*inp[0])).hex()]
        cout = [Z.compress(Z.commit(v, r)).hex() for v, r in zip(out_v, out_r)]
        ctx = Z._tx_ctx(cin, cout, 0)
        good = Z.range_prove(150, out_r[0], ctx + b"\x00")
        stolen = Z.range_prove(5, out_r[1], ctx + b"\x01")           # a proof for some other amount
        tx = {"inputs": cin, "fee": 0, "outputs": [{"C": cout[0], "range": good}, {"C": cout[1], "range": stolen}],
              "balance": Z._balance_prove((inp[0][1] - sum(out_r)) % Z.L, Z._excess_point(cin, cout, 0), ctx)}
        self.assertFalse(Z.verify_tx(tx)[0])

    def test_tampering_and_replay(self):
        tx, _ = Z.build_tx([(50, Z.rand_scalar())], [20, 29], 1)
        for mutate in (lambda t: t.update(fee=0), lambda t: t["inputs"].append(t["inputs"][0]),
                       lambda t: t["outputs"].reverse(), lambda t: t["outputs"].pop(),
                       lambda t: t["balance"].update(s="0" * 64), lambda t: t.pop("balance")):
            bad = copy.deepcopy(tx)
            mutate(bad)
            self.assertFalse(Z.verify_tx(bad)[0])
        other, _ = Z.build_tx([(50, Z.rand_scalar())], [20, 29], 1)
        replay = copy.deepcopy(other)
        replay["outputs"][0] = tx["outputs"][0]                   # proof lifted from another transaction
        self.assertFalse(Z.verify_tx(replay)[0])

    def test_garbage_never_crashes(self):
        for junk in ({}, {"inputs": 5}, {"inputs": ["zz"], "outputs": [], "fee": 0}, {"inputs": [], "outputs": [{}], "fee": -1}):
            self.assertFalse(Z.verify_tx(junk)[0])


if __name__ == "__main__":
    unittest.main()
