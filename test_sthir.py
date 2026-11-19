import time
import unittest

from sthir import (
    UNIT, Block, InvalidBlock, Node, Params, Tx, Wallet, block_reward,
    meets_difficulty,
)

P = Params(blocks_per_year=20, difficulty_bits=8)


class EmissionTests(unittest.TestCase):
    def test_initial_phase_totals_21m(self):
        total = sum(block_reward(h, 0, P) for h in range(1, 8 * P.blocks_per_year + 1))
        # integer division loses a few base units; allow tiny rounding error
        self.assertAlmostEqual(total / UNIT, 21_000_000, delta=0.01)

    def test_halving_after_four_years(self):
        four = 4 * P.blocks_per_year
        self.assertEqual(block_reward(four, 0, P), 2 * block_reward(four + 1, 0, P))

    def test_tail_is_about_one_percent_per_year(self):
        supply = 21_000_000 * UNIT
        per_year = block_reward(9 * P.blocks_per_year, supply, P) * P.blocks_per_year
        self.assertAlmostEqual(per_year / supply, 0.01, places=3)

    def test_no_premine(self):
        self.assertEqual(Node(P).supply, 0)


class ChainTests(unittest.TestCase):
    def setUp(self):
        self.n = Node(P, "n")
        self.alice, self.bob = Wallet(), Wallet()
        for _ in range(2):
            self.n.mine(self.alice.address)

    def test_valid_payment(self):
        self.n.submit_tx(Tx.create(self.alice, self.bob.address, 3 * UNIT, 0, 0))
        self.n.mine(self.alice.address)
        self.assertEqual(self.n.balances[self.bob.address], 3 * UNIT)

    def test_supply_matches_sum_of_balances(self):
        self.n.submit_tx(Tx.create(self.alice, self.bob.address, 3 * UNIT, 1000, 0))
        self.n.mine(self.bob.address)
        self.assertEqual(sum(self.n.balances.values()), self.n.supply)

    def test_bad_signature_rejected(self):
        tx = Tx.create(self.alice, self.bob.address, UNIT, 0, 0)
        forged = Tx(tx.sender, tx.recipient, 99 * UNIT, tx.fee, tx.nonce, tx.signature)
        with self.assertRaises(InvalidBlock):
            self.n.submit_tx(forged)

    def test_cannot_spend_more_than_balance(self):
        too_much = self.n.balances[self.alice.address] + 1
        with self.assertRaises(InvalidBlock):
            self.n.submit_tx(Tx.create(self.alice, self.bob.address, too_much, 0, 0))

    def test_replay_rejected(self):
        tx = Tx.create(self.alice, self.bob.address, UNIT, 0, 0)
        self.n.submit_tx(tx)
        self.n.mine(self.alice.address)
        with self.assertRaises(InvalidBlock):
            self.n.submit_tx(tx)

    def test_double_spend_in_one_block_rejected(self):
        bal = self.n.balances[self.alice.address]
        t1 = Tx.create(self.alice, self.bob.address, bal, 0, 0)
        t2 = Tx.create(self.alice, self.bob.address, bal, 0, 1)
        block = Block(
            self.n.tip.height + 1, self.n.tip.hash(), self.n.tip.timestamp,
            self.alice.address,
            block_reward(self.n.tip.height + 1, self.n.supply, P), [t1, t2],
        )
        while not meets_difficulty(block.hash(), P.initial_difficulty):
            block.nonce += 1
        with self.assertRaises(InvalidBlock):
            self.n.add_block(block)

    def test_inflated_reward_rejected(self):
        block = Block(
            self.n.tip.height + 1, self.n.tip.hash(), self.n.tip.timestamp,
            self.alice.address,
            block_reward(self.n.tip.height + 1, self.n.supply, P) + 1, [],
        )
        while not meets_difficulty(block.hash(), P.initial_difficulty):
            block.nonce += 1
        with self.assertRaises(InvalidBlock):
            self.n.add_block(block)

    def test_insufficient_pow_rejected(self):
        block = Block(
            self.n.tip.height + 1, self.n.tip.hash(), self.n.tip.timestamp,
            self.alice.address,
            block_reward(self.n.tip.height + 1, self.n.supply, P), [],
        )
        while meets_difficulty(block.hash(), P.initial_difficulty):
            block.nonce += 1
        with self.assertRaises(InvalidBlock):
            self.n.add_block(block)


class SyncTests(unittest.TestCase):
    def test_two_nodes_converge(self):
        a, b = Node(P, "A"), Node(P, "B")
        w = Wallet()
        for _ in range(4):
            a.mine(w.address)
        self.assertTrue(b.sync_from(a))
        self.assertEqual(a.tip.hash(), b.tip.hash())
        self.assertEqual(a.supply, b.supply)

    def test_fork_resolves_to_longer_chain(self):
        a, b = Node(P, "A"), Node(P, "B")
        wa, wb = Wallet(), Wallet()
        a.mine(wa.address)
        b.mine(wb.address)
        for _ in range(2):
            b.mine(wb.address)  # B now has the heavier chain
        self.assertTrue(a.sync_from(b))
        self.assertEqual(a.tip.hash(), b.tip.hash())
        self.assertNotIn(wa.address, a.balances)  # A's orphaned reward is gone

    def test_invalid_chain_not_adopted(self):
        a, b = Node(P, "A"), Node(P, "B")
        w = Wallet()
        for _ in range(3):
            b.mine(w.address)
        bad = b.chain[2]
        bad.reward += 1  # tamper after the fact
        self.assertRaises(InvalidBlock, a.sync_from, b)
        self.assertEqual(a.tip.height, 0)


RP = Params(blocks_per_year=20, difficulty_bits=6, target_block_time=10,
            retarget_interval=6)
BASE = int(time.time()) - 100_000


def mine_run(node, miner, count, spacing):
    """Mine `count` blocks whose timestamps are `spacing` seconds apart."""
    ts = node.tip.timestamp or BASE
    for _ in range(count):
        ts += spacing
        node.mine(miner, timestamp=ts)


class RetargetTests(unittest.TestCase):
    def setUp(self):
        self.w = Wallet()

    def test_starts_at_initial_difficulty(self):
        self.assertEqual(Node(RP).next_difficulty(), RP.initial_difficulty)

    def test_fast_blocks_raise_difficulty_clamped_to_4x(self):
        n = Node(RP)
        mine_run(n, self.w.address, 5, 1)  # intended 10 s apart, actual 1 s
        self.assertEqual(n.next_difficulty(), 4 * RP.initial_difficulty)

    def test_on_target_blocks_keep_difficulty(self):
        n = Node(RP)
        mine_run(n, self.w.address, 5, 10)
        self.assertEqual(n.next_difficulty(), RP.initial_difficulty)

    def test_slow_blocks_never_go_below_starting_difficulty(self):
        n = Node(RP)
        mine_run(n, self.w.address, 5, 1000)
        self.assertEqual(n.next_difficulty(), RP.initial_difficulty)

    def test_slow_blocks_lower_a_raised_difficulty(self):
        n = Node(RP)
        mine_run(n, self.w.address, 5, 1)  # raises to 4x at block 6
        mine_run(n, self.w.address, 6, 100)  # blocks 6..11, far too slow
        self.assertEqual(n.next_difficulty(), RP.initial_difficulty)

    def _weak_block6(self, node):
        """A block-6 candidate that meets the old difficulty but not the new."""
        h = node.tip.height + 1
        blk = Block(h, node.tip.hash(), node.tip.timestamp + 1, self.w.address,
                    block_reward(h, node.supply, RP), [])
        need = node.next_difficulty()
        while not (meets_difficulty(blk.hash(), RP.initial_difficulty)
                   and not meets_difficulty(blk.hash(), need)):
            blk.nonce += 1
        return blk

    def test_block_at_old_difficulty_rejected_after_retarget(self):
        n = Node(RP)
        mine_run(n, self.w.address, 5, 1)
        with self.assertRaises(InvalidBlock) as cm:
            n.add_block(self._weak_block6(n))
        self.assertIn("proof of work", str(cm.exception))

    def test_chain_with_forged_easy_difficulty_not_adopted(self):
        src = Node(RP)
        mine_run(src, self.w.address, 5, 1)
        bad = self._weak_block6(src)
        victim = Node(RP)
        with self.assertRaises(InvalidBlock):
            victim.adopt_chain(src.chain[1:] + [bad])
        self.assertEqual(victim.tip.height, 0)

    def test_peers_agree_on_difficulty_and_work(self):
        a, b = Node(RP), Node(RP)
        mine_run(a, self.w.address, 8, 1)
        self.assertTrue(b.sync_from(a))
        self.assertEqual(a.next_difficulty(), b.next_difficulty())
        self.assertEqual(a.total_work(), b.total_work())
        self.assertGreater(a.next_difficulty(), RP.initial_difficulty)


if __name__ == "__main__":
    unittest.main()
