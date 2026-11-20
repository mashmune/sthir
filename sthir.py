"""Sthir prototype v0.1

A minimal, in-process blockchain that follows the whitepaper's rules:
  - fixed initial supply (21,000,000 coins) with a halving schedule, then
    a ~1% per year tail emission, zero premine
  - signed transactions (Ed25519), account model with nonces
  - Proof-of-Work (SHA-256 here; RandomX is a later phase) whose difficulty
    retargets every N blocks, so the chain keeps a steady block time
  - heaviest-chain rule, so two nodes can sync and converge

This is an experimental prototype, not production money. No networking yet:
nodes exchange blocks by direct method calls.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------- parameters
UNIT = 10**8  # 1 coin = 10^8 base units
BLOCKS_PER_YEAR = 105_120  # one year of 300 s blocks; tests override via Params
INITIAL_SUPPLY_COINS = 21_000_000
# Phase 1: first 4 years pay 2/3 of 21M, next 4 years pay 1/3 (a halving).
PHASE1_COINS = 14_000_000
PHASE2_COINS = 7_000_000
TAIL_RATE_PER_YEAR = 0.01  # 1% of circulating supply per year, forever


@dataclass(frozen=True)
class Params:
    blocks_per_year: int = BLOCKS_PER_YEAR
    difficulty_bits: int = 16  # starting difficulty is 2**bits hashes per block
    max_future_seconds: int = 7200
    target_block_time: int = 300  # seconds
    retarget_interval: int = 144  # blocks between difficulty adjustments

    @property
    def initial_difficulty(self) -> int:
        return 1 << self.difficulty_bits


def block_reward(height: int, supply: int, p: Params) -> int:
    """Reward (in base units) for a block at `height` given circulating supply.

    Deterministic integer math so every node computes the same number.
    """
    if height == 0:
        return 0
    four_years = 4 * p.blocks_per_year
    if height <= four_years:
        return PHASE1_COINS * UNIT // four_years
    if height <= 2 * four_years:
        return PHASE2_COINS * UNIT // four_years
    # Tail emission: 1% of supply per year spread over the year's blocks.
    return supply * 1 // (100 * p.blocks_per_year)


# -------------------------------------------------------------------- crypto
def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Wallet:
    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._sk = private_key or Ed25519PrivateKey.generate()
        raw = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.address = raw.hex()

    def sign(self, message: bytes) -> str:
        return self._sk.sign(message).hex()


def verify_sig(address: str, message: bytes, signature: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(address)).verify(
            bytes.fromhex(signature), message
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------- transaction
@dataclass(frozen=True)
class Tx:
    sender: str
    recipient: str
    amount: int  # base units
    fee: int
    nonce: int
    signature: str = ""

    def body(self) -> bytes:
        return json.dumps(
            [self.sender, self.recipient, self.amount, self.fee, self.nonce],
            separators=(",", ":"),
        ).encode()

    def txid(self) -> str:
        return _h(self.body() + bytes.fromhex(self.signature or "00"))

    @staticmethod
    def create(wallet: Wallet, recipient: str, amount: int, fee: int, nonce: int) -> "Tx":
        unsigned = Tx(wallet.address, recipient, amount, fee, nonce)
        return Tx(
            wallet.address, recipient, amount, fee, nonce, wallet.sign(unsigned.body())
        )


# --------------------------------------------------------------------- block
@dataclass
class Block:
    height: int
    prev_hash: str
    timestamp: int
    miner: str
    reward: int
    txs: list[Tx] = field(default_factory=list)
    nonce: int = 0

    def tx_root(self) -> str:
        return _h("".join(t.txid() for t in self.txs).encode())

    def header(self) -> bytes:
        return json.dumps(
            [self.height, self.prev_hash, self.timestamp, self.miner,
             self.reward, self.tx_root(), self.nonce],
            separators=(",", ":"),
        ).encode()

    def hash(self) -> str:
        return _h(self.header())


def meets_difficulty(block_hash: str, difficulty: int) -> bool:
    """Valid proof of work: hash * difficulty < 2**256 (exact integer test).

    A difficulty of D means about D hashes are needed to find a block.
    """
    return int(block_hash, 16) * difficulty < 2**256


# ---------------------------------------------------------------------- node
class InvalidBlock(Exception):
    pass


class Node:
    def __init__(self, params: Params | None = None, name: str = "node"):
        self.p = params or Params()
        self.name = name
        self.genesis = Block(0, "0" * 64, 0, "0" * 64, 0)
        self.chain: list[Block] = [self.genesis]
        self.diffs: list[int] = [self.p.initial_difficulty]  # diffs[i] = block i's
        self.work = 0  # sum of the difficulties of all blocks after genesis
        self.balances: dict[str, int] = {}
        self.nonces: dict[str, int] = {}
        self.supply = 0
        self.mempool: list[Tx] = []

    # ------------------------------------------------------------ state rules
    @property
    def tip(self) -> Block:
        return self.chain[-1]

    def total_work(self) -> int:
        return self.work

    def next_difficulty(self) -> int:
        """Difficulty the next block must meet, derived only from the chain."""
        return self._difficulty_for(self.chain, self.diffs)

    def _difficulty_for(self, chain: list[Block], diffs: list[int]) -> int:
        """Required difficulty for a new block on top of `chain`.

        Every `retarget_interval` blocks the difficulty is multiplied by
        (intended time / actual time) of the blocks in the window, clamped to
        4x in either direction and never below the starting difficulty.
        Integer math only, so every node computes exactly the same value.
        """
        p = self.p
        height = len(chain)  # height of the block being built
        prev = diffs[-1]
        n = p.retarget_interval
        if n < 3 or height % n != 0:
            return prev
        first, last = max(height - n, 1), height - 1  # skip genesis (ts 0)
        expected = (last - first) * p.target_block_time
        actual = chain[last].timestamp - chain[first].timestamp
        actual = max(min(actual, expected * 4), expected // 4, 1)
        return max(prev * expected // actual, p.initial_difficulty)

    def _apply(self, block: Block, balances, nonces, supply) -> int:
        """Validate `block` against given state, mutate it, return new supply."""
        expected_reward = block_reward(block.height, supply, self.p)
        fees = 0
        for tx in block.txs:
            if tx.amount <= 0 or tx.fee < 0:
                raise InvalidBlock("bad amount or fee")
            if not verify_sig(tx.sender, tx.body(), tx.signature):
                raise InvalidBlock("bad signature")
            if nonces.get(tx.sender, 0) != tx.nonce:
                raise InvalidBlock("bad nonce (replay or double spend)")
            if balances.get(tx.sender, 0) < tx.amount + tx.fee:
                raise InvalidBlock("insufficient balance")
            balances[tx.sender] -= tx.amount + tx.fee
            balances[tx.recipient] = balances.get(tx.recipient, 0) + tx.amount
            nonces[tx.sender] = tx.nonce + 1
            fees += tx.fee
        if block.reward != expected_reward:
            raise InvalidBlock(
                f"wrong reward {block.reward}, expected {expected_reward}"
            )
        payout = block.reward + fees
        balances[block.miner] = balances.get(block.miner, 0) + payout
        return supply + block.reward  # fees move coins, they do not mint

    def _check_header(self, block: Block, prev: Block, difficulty: int) -> None:
        if block.height != prev.height + 1:
            raise InvalidBlock("bad height")
        if block.prev_hash != prev.hash():
            raise InvalidBlock("bad prev_hash")
        if not meets_difficulty(block.hash(), difficulty):
            raise InvalidBlock("insufficient proof of work")
        if block.timestamp > int(time.time()) + self.p.max_future_seconds:
            raise InvalidBlock("timestamp too far in future")
        if block.timestamp < prev.timestamp:
            raise InvalidBlock("timestamp before parent")

    # --------------------------------------------------------------- accept
    def add_block(self, block: Block) -> None:
        diff = self.next_difficulty()
        self._check_header(block, self.tip, diff)
        balances, nonces = dict(self.balances), dict(self.nonces)
        new_supply = self._apply(block, balances, nonces, self.supply)
        self.chain.append(block)
        self.diffs.append(diff)
        self.work += diff
        self.balances, self.nonces, self.supply = balances, nonces, new_supply
        included = {t.txid() for t in block.txs}
        self.mempool = [t for t in self.mempool if t.txid() not in included]

    def submit_tx(self, tx: Tx) -> None:
        """Mempool admission: same checks a block would apply, on top of mempool."""
        if not verify_sig(tx.sender, tx.body(), tx.signature):
            raise InvalidBlock("bad signature")
        pending = [t for t in self.mempool if t.sender == tx.sender]
        next_nonce = self.nonces.get(tx.sender, 0) + len(pending)
        if tx.nonce != next_nonce:
            raise InvalidBlock("bad nonce")
        reserved = sum(t.amount + t.fee for t in pending)
        if self.balances.get(tx.sender, 0) < reserved + tx.amount + tx.fee:
            raise InvalidBlock("insufficient balance")
        self.mempool.append(tx)

    # ---------------------------------------------------------------- mining
    def mine(self, miner_address: str, timestamp: int | None = None) -> Block:
        txs = list(self.mempool)
        height = self.tip.height + 1
        block = Block(
            height=height,
            prev_hash=self.tip.hash(),
            timestamp=max(timestamp or int(time.time()), self.tip.timestamp),
            miner=miner_address,
            reward=block_reward(height, self.supply, self.p),
            txs=txs,
        )
        diff = self.next_difficulty()
        while not meets_difficulty(block.hash(), diff):
            block.nonce += 1
        self.add_block(block)
        return block

    # ------------------------------------------------------------------ sync
    def adopt_chain(self, blocks: list[Block]) -> bool:
        """Adopt the chain `blocks` (everything after genesis) if it is valid
        and carries more total work than ours.

        Every block is checked from genesis on a scratch state, including the
        difficulty it had to meet, so a peer cannot feed us an invalid chain
        or one mined at a forged easy difficulty. Work is computed from our
        own validation, never from what the peer claims. Raises InvalidBlock
        for an invalid chain; returns True only if we switched.
        """
        chain: list[Block] = [self.genesis]
        diffs: list[int] = [self.p.initial_difficulty]
        balances: dict[str, int] = {}
        nonces: dict[str, int] = {}
        supply = 0
        work = 0
        for block in blocks:
            diff = self._difficulty_for(chain, diffs)
            self._check_header(block, chain[-1], diff)
            supply = self._apply(block, balances, nonces, supply)
            chain.append(block)
            diffs.append(diff)
            work += diff
        if work <= self.work:
            return False
        self.chain, self.diffs, self.work = chain, diffs, work
        self.balances, self.nonces, self.supply = balances, nonces, supply
        on_chain = {t.txid() for b in self.chain for t in b.txs}
        self.mempool = [t for t in self.mempool if t.txid() not in on_chain]
        return True

    def sync_from(self, other: "Node") -> bool:
        """Adopt `other`'s chain if it is valid and has more total work."""
        return self.adopt_chain(other.chain[1:])


# ---------------------------------------------------------------------- demo
def _demo() -> None:
    p = Params(blocks_per_year=50, difficulty_bits=12)
    a, b = Node(p, "A"), Node(p, "B")
    alice, bob = Wallet(), Wallet()

    for _ in range(3):
        a.mine(alice.address)
    print(f"A mined 3 blocks. Alice balance: {a.balances[alice.address] / UNIT:.2f}")

    a.submit_tx(Tx.create(alice, bob.address, 5 * UNIT, UNIT // 100, 0))
    a.mine(alice.address)
    print(f"Alice paid Bob 5. Bob balance: {a.balances[bob.address] / UNIT:.2f}")

    print("B syncs from A:", b.sync_from(a), "| same tip:", a.tip.hash() == b.tip.hash())
    print(f"Supply on both nodes: {a.supply / UNIT:.2f} = {b.supply / UNIT:.2f}")


if __name__ == "__main__":
    _demo()
