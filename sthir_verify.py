"""Sthir verifiable compute: a heavy node proves, a phone checks.

This is NOT a zero-knowledge proof. It is the cheaper, older idea behind optimistic
rollups, applied to a task that is a long chain of small deterministic steps:

    state_0 -> state_1 -> ... -> state_N        (state_{i+1} = step(state_i, i))

1. COMMIT. The heavy node runs all N steps, hashes every state into a Merkle tree and
   publishes only (seed, N, root, final_state).
2. SPOT CHECK (phone, cheap). Pick k step indexes from a hash of the claim. The prover
   opens state_i and state_{i+1} with Merkle paths; the phone re-runs ONE step each.
   Cost for the phone: k steps + 2k*log2(N) hashes, instead of N steps.
   Catches a cheater who corrupts a fraction f of the steps with probability
   1 - (1 - f)^k. A cheater who corrupts ONE step is caught only with probability k/N.
3. DISPUTE (anyone who re-runs the task). If a challenger sees a different final state
   it bisects the trace with the prover: log2(N) rounds, each one Merkle opening, down
   to a single step. The phone then acts as referee and re-runs that single step.
   This catches even one wrong step, provided at least one honest challenger exists.

The toy kernel below (an affine map over GF(2^31 - 1)) stands in for a real workload.
Real medical or AI tasks need a step function with a small, exactly reproducible state;
that is the hard engineering part, and it is not solved here.
"""
from __future__ import annotations

import hashlib
import json
import math

P = 2 ** 31 - 1
DIM = 8
KERNEL = "affine-v1"


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ----------------------------------------------------------------- the toy kernel
def _stream(seed: bytes, n: int) -> list[int]:
    out, ctr = [], 0
    while len(out) < n:
        out.append(int.from_bytes(_h(seed + ctr.to_bytes(4, "big"))[:8], "big") % P)
        ctr += 1
    return out


def make_kernel(seed: bytes):
    vals = _stream(b"kernel|" + seed, DIM * DIM + DIM)
    A = [vals[r * DIM:(r + 1) * DIM] for r in range(DIM)]
    b = vals[DIM * DIM:]
    return A, b


def initial_state(seed: bytes) -> tuple:
    return tuple(_stream(b"init|" + seed, DIM))


def step(kernel, state: tuple, i: int) -> tuple:
    A, b = kernel
    return tuple((sum(A[r][c] * state[c] for c in range(DIM)) + b[r] + i) % P for r in range(DIM))


def enc(state: tuple) -> bytes:
    return b"".join(x.to_bytes(4, "big") for x in state)


def dec(hexs: str) -> tuple:
    raw = bytes.fromhex(hexs)
    if len(raw) != 4 * DIM:
        raise ValueError("bad state")
    return tuple(int.from_bytes(raw[i:i + 4], "big") for i in range(0, len(raw), 4))


# ------------------------------------------------------------------- merkle tree
def _leaf(state: tuple) -> bytes:
    return _h(b"L" + enc(state))


def _node(a: bytes, b: bytes) -> bytes:
    return _h(b"N" + a + b)


def _levels(leaves: list[bytes]) -> list[list[bytes]]:
    lv = [leaves]
    while len(lv[-1]) > 1:
        cur, nxt = lv[-1], []
        for i in range(0, len(cur), 2):
            nxt.append(_node(cur[i], cur[i + 1]) if i + 1 < len(cur) else cur[i])
        lv.append(nxt)
    return lv


def _path(levels, i: int) -> list[str]:
    out = []
    for lv in levels[:-1]:
        sib = i ^ 1
        out.append(lv[sib].hex() if sib < len(lv) else "")   # "" = no sibling at this level
        i //= 2
    return out


def _check_path(root: bytes, leaf: bytes, i: int, n_leaves: int, path: list[str]) -> bool:
    size, cur = n_leaves, leaf
    if len(path) != max(math.ceil(math.log2(n_leaves)) if n_leaves > 1 else 0, 0):
        return False
    for sib in path:
        if sib:
            s = bytes.fromhex(sib)
            cur = _node(s, cur) if i & 1 else _node(cur, s)
        elif (i ^ 1) < size:
            return False                        # a sibling existed but none was given
        i //= 2
        size = (size + 1) // 2
    return cur == root


# ----------------------------------------------------------------- the heavy node
class Prover:
    def __init__(self, seed: bytes, steps: int, cheat_at: int | None = None):
        if not 2 <= steps <= 1 << 20:
            raise ValueError("steps out of range")
        self.seed, self.steps = seed, steps
        self.kernel = make_kernel(seed)
        st = [initial_state(seed)]
        for i in range(steps):
            nxt = step(self.kernel, st[-1], i)
            if cheat_at is not None and i == cheat_at:
                nxt = ((nxt[0] + 1) % P,) + nxt[1:]        # one wrong transition, then carry on
            st.append(nxt)
        self.states = st
        self.levels = _levels([_leaf(s) for s in st])

    def claim(self) -> dict:
        return {"kernel": KERNEL, "seed": self.seed.hex(), "steps": self.steps,
                "root": self.levels[-1][0].hex(), "final": enc(self.states[-1]).hex()}

    def open(self, i: int) -> dict:
        return {"i": i, "state": enc(self.states[i]).hex(), "path": _path(self.levels, i)}


# ------------------------------------------------------------------ the phone side
def sample_indices(claim: dict, k: int) -> list[int]:
    """Step indexes to check, fixed by the claim itself so the prover cannot pick them."""
    seed = hashlib.sha256(json.dumps(claim, sort_keys=True).encode()).digest()
    n, out, ctr = claim["steps"], [], 0
    while len(out) < min(k, n):
        i = int.from_bytes(_h(seed + ctr.to_bytes(4, "big"))[:8], "big") % n
        ctr += 1
        if i not in out:
            out.append(i)
    return out


def _opened(claim: dict, op: dict) -> tuple | None:
    """The state of an opening if its Merkle path matches the committed root, else None."""
    try:
        st = dec(op["state"])
        i = int(op["i"])
        if not 0 <= i <= claim["steps"]:
            return None
        ok = _check_path(bytes.fromhex(claim["root"]), _leaf(st), i, claim["steps"] + 1, op["path"])
        return st if ok else None
    except (KeyError, ValueError, TypeError):
        return None


def verify_samples(claim: dict, openings: dict, k: int = 16) -> dict:
    """openings: {"first": op(0), "last": op(N), "pairs": [[op(i), op(i+1)], ...]}.
    Returns {"ok": bool, "reason": str, "cost": {...}}."""
    cost = {"steps_rerun": 0, "hashes": 0}
    try:
        if claim.get("kernel") != KERNEL or not 2 <= int(claim["steps"]) <= 1 << 20:
            return {"ok": False, "reason": "unknown kernel or step count", "cost": cost}
        seed, n = bytes.fromhex(claim["seed"]), int(claim["steps"])
        kernel = make_kernel(seed)
        first, last = _opened(claim, openings["first"]), _opened(claim, openings["last"])
        cost["hashes"] += 2 * (n.bit_length() + 1)
        if first is None or openings["first"]["i"] != 0 or first != initial_state(seed):
            return {"ok": False, "reason": "start state is wrong", "cost": cost}
        if last is None or openings["last"]["i"] != n or enc(last).hex() != claim["final"]:
            return {"ok": False, "reason": "final state is not the committed one", "cost": cost}
        want = sample_indices(claim, k)
        got = {int(p[0]["i"]): p for p in openings["pairs"]}
        for i in want:
            if i not in got:
                return {"ok": False, "reason": f"missing opening for step {i}", "cost": cost}
            a, b = _opened(claim, got[i][0]), _opened(claim, got[i][1])
            cost["hashes"] += 2 * (n.bit_length() + 1)
            if a is None or b is None or int(got[i][1]["i"]) != i + 1:
                return {"ok": False, "reason": f"bad Merkle path at step {i}", "cost": cost}
            cost["steps_rerun"] += 1
            if step(kernel, a, i) != b:
                return {"ok": False, "reason": f"step {i} is wrong", "cost": cost}
    except (KeyError, ValueError, TypeError, IndexError, AttributeError):
        return {"ok": False, "reason": "malformed proof", "cost": cost}
    return {"ok": True, "reason": "all sampled steps check out", "cost": cost}


def sample_openings(prover: Prover, k: int = 16) -> dict:
    cl = prover.claim()
    return {"first": prover.open(0), "last": prover.open(prover.steps),
            "pairs": [[prover.open(i), prover.open(i + 1)] for i in sample_indices(cl, k)]}


# ---------------------------------------------------------------------- the dispute
def bisect(prover: Prover, honest: Prover) -> dict:
    """A challenger holding the honest trace narrows the prover's trace to one step.
    Returns the two openings the referee needs, and the number of rounds used."""
    lo, hi, rounds = 0, prover.steps, 0
    if prover.states[0] != honest.states[0]:
        raise ValueError("start states differ: no dispute needed, the verifier sees it directly")
    if prover.states[hi] == honest.states[hi]:
        raise ValueError("final states agree: nothing to dispute")
    while hi - lo > 1:
        mid = (lo + hi) // 2
        rounds += 1
        if prover.states[mid] == honest.states[mid]:    # challenger compares the opened state to its own
            lo = mid
        else:
            hi = mid
    return {"lo": prover.open(lo), "hi": prover.open(hi), "rounds": rounds}


def referee(claim: dict, lo: dict, hi: dict) -> dict:
    """The phone's whole job in a dispute: re-run one step. Decides whether the
    prover's committed trace contains an invalid transition."""
    a, b = _opened(claim, lo), _opened(claim, hi)
    if a is None or b is None:
        return {"fraud_proven": False, "reason": "openings do not match the committed root"}
    i = int(lo["i"])
    if int(hi["i"]) != i + 1:
        return {"fraud_proven": False, "reason": "openings are not adjacent"}
    if step(make_kernel(bytes.fromhex(claim["seed"])), a, i) == b:
        return {"fraud_proven": False, "reason": "that step is valid: the challenge fails"}
    return {"fraud_proven": True, "step": i, "reason": f"committed step {i} is not the kernel's output"}


# ------------------------------------------------------------------------- demo
def demo() -> None:
    import random
    n, k = 512, 16
    seed = b"sthir-demo"
    honest = Prover(seed, n)
    cl = honest.claim()
    r = verify_samples(cl, sample_openings(honest, k), k)
    print(f"Honest heavy node, {n} steps committed under root {cl['root'][:16]}...")
    print(f"  phone check: ok={r['ok']}  re-ran {r['cost']['steps_rerun']} of {n} steps, {r['cost']['hashes']} hashes")

    rng, caught, trials = random.Random(7), 0, 150
    for _ in range(trials):
        cheat = Prover(seed, n, cheat_at=rng.randrange(n))
        if not verify_samples(cheat.claim(), sample_openings(cheat, k), k)["ok"]:
            caught += 1
    print(f"\nOne corrupted step, spot check only (k={k}): caught {caught}/{trials} = {caught / trials:.1%}")
    print(f"  theory k/N = {k / n:.1%}.  Spot checks alone do NOT stop a one-step cheat.")

    cheat = Prover(seed, n, cheat_at=300)
    d = bisect(cheat, honest)
    ref = referee(cheat.claim(), d["lo"], d["hi"])
    print(f"\nDispute: challenger re-runs the task and bisects. {d['rounds']} rounds (log2 {n} = {math.log2(n):.0f}).")
    print(f"  phone as referee: fraud_proven={ref['fraud_proven']} at step {ref.get('step')}  (cheater hid it at step 300)")
    liar = referee(honest.claim(), honest.open(10), honest.open(11))
    print(f"  false challenge against an honest node: fraud_proven={liar['fraud_proven']} ({liar['reason']})")


if __name__ == "__main__":
    demo()
