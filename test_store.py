import json
import os
import tempfile
import unittest

from sthir import Node, Params, Wallet
from sthir_net import ChainStore

P = Params(blocks_per_year=20, difficulty_bits=6, target_block_time=10,
           retarget_interval=6)
RULES = [6, 10, 6]


def mined(n, seed_wallet=None):
    node = Node(P)
    w = seed_wallet or Wallet()
    for _ in range(n):
        node.mine(w.address)
    return node, w


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "data")

    def tearDown(self):
        self.tmp.cleanup()

    def test_blocks_survive_a_restart(self):
        node, w = mined(8)
        store = ChainStore(self.dir, RULES)
        for b in node.chain[1:]:
            store.append(b)
        fresh = Node(P)
        self.assertTrue(fresh.adopt_chain(ChainStore(self.dir, RULES).load()))
        self.assertEqual(fresh.tip.hash(), node.tip.hash())
        self.assertEqual(fresh.balances, node.balances)
        self.assertEqual(fresh.supply, node.supply)
        self.assertEqual(fresh.total_work(), node.total_work())

    def test_empty_folder_loads_nothing(self):
        self.assertEqual(ChainStore(self.dir, RULES).load(), [])

    def test_torn_last_line_is_dropped_and_file_repaired(self):
        node, _ = mined(5)
        store = ChainStore(self.dir, RULES)
        store.rewrite(node.chain[1:])
        with open(store.chain_file, "ab") as f:
            f.write(b'{"height":6,"prev_hash":"abc')  # crash in the middle of a write
        blocks = ChainStore(self.dir, RULES).load()
        self.assertEqual(len(blocks), 5)
        with open(store.chain_file, "rb") as f:
            self.assertTrue(f.read().endswith(b"\n"))
        self.assertEqual(len(ChainStore(self.dir, RULES).load()), 5)

    def test_damage_in_the_middle_refuses_to_start(self):
        node, _ = mined(5)
        store = ChainStore(self.dir, RULES)
        store.rewrite(node.chain[1:])
        lines = open(store.chain_file).read().splitlines()
        lines[2] = lines[2][:20]
        open(store.chain_file, "w").write("\n".join(lines) + "\n")
        with self.assertRaises(SystemExit):
            ChainStore(self.dir, RULES).load()

    def test_edited_block_is_rejected_by_validation(self):
        node, _ = mined(5)
        store = ChainStore(self.dir, RULES)
        store.rewrite(node.chain[1:])
        rows = [json.loads(x) for x in open(store.chain_file)]
        rows[3]["reward"] += 10**8  # someone edits the file to print coins
        open(store.chain_file, "w").write("".join(json.dumps(r) + "\n" for r in rows))
        loaded = ChainStore(self.dir, RULES).load()
        from sthir import InvalidBlock
        with self.assertRaises(InvalidBlock):
            Node(P).adopt_chain(loaded)

    def test_different_rules_refuse_to_load(self):
        node, _ = mined(3)
        ChainStore(self.dir, RULES).rewrite(node.chain[1:])
        with self.assertRaises(SystemExit):
            ChainStore(self.dir, [7, 10, 6]).load()

    def test_rewrite_replaces_the_chain_after_a_reorg(self):
        a, _ = mined(3)
        store = ChainStore(self.dir, RULES)
        for b in a.chain[1:]:
            store.append(b)
        b, _ = mined(5)  # a different, heavier chain
        store.rewrite(b.chain[1:])
        loaded = ChainStore(self.dir, RULES).load()
        self.assertEqual([x.hash() for x in loaded], [x.hash() for x in b.chain[1:]])
        self.assertFalse(os.path.exists(store.chain_file + ".tmp"))


if __name__ == "__main__":
    unittest.main()
