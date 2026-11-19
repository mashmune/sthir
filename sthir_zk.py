"""Sthir confidential amounts: real zero-knowledge proofs, small and readable.

What is proven, without revealing any amount:
  * RANGE   each output amount v is in [0, 2^32): nobody can create coins with a "negative" amount.
  * BALANCE sum(inputs) = sum(outputs) + fee: no coins appear from nowhere.
Together these are a Confidential Transaction (the construction used by Monero/Elements,
here with simple bit proofs instead of Bulletproofs, so proofs are about 4 KB per output).

Building blocks (all textbook, non-interactive via Fiat-Shamir):
  Pedersen commitment      C = v*G + r*H           hides v, binds the committer to v
  Bit proof (OR-proof)     C opens to 0 or to 1, without saying which
  Range proof              v = sum(b_i 2^i): one commitment and one bit proof per bit
  Balance (Schnorr) proof  the leftover point is a pure multiple of H, i.e. it carries no value

HONEST LIMITS
  * This is NOT a zk-SNARK or zk-STARK and cannot prove "this heavy computation ran correctly".
    Proving arbitrary compute in zero knowledge is still far too expensive for a phone.
  * Pure Python, variable-time arithmetic, not audited. Do not protect real money with it.
  * Proofs alone do not make a private chain: it also needs note encryption to the receiver,
    nullifiers or key images against double-spending, and consensus rules. Not built here.
"""
from __future__ import annotations

import hashlib
import secrets

p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493       # order of the prime subgroup
d = -121665 * pow(121666, -1, p) % p
BITS = 32


# ------------------------------------------------------------------- the curve
def add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A, B = (Y1 - X1) * (Y2 - X2) % p, (Y1 + X1) * (Y2 + X2) % p
    C, D = T1 * 2 * d * T2 % p, Z1 * 2 * Z2 % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


ZERO = (0, 1, 1, 0)


def neg(P):
    return ((-P[0]) % p, P[1], P[2], (-P[3]) % p)


def mul(k: int, P, reduce: bool = True):
    if reduce:
        k %= L
    R = ZERO
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R


def eq(P, Q) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _recover_x(y: int, sign: int):
    x2 = (y * y - 1) * pow(d * y * y + 1, -1, p) % p
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * pow(2, (p - 1) // 4, p) % p
    if (x * x - x2) % p:
        return None
    return p - x if (x & 1) != sign else x


def compress(P) -> bytes:
    zi = pow(P[2], -1, p)
    x, y = P[0] * zi % p, P[1] * zi % p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decompress(b: bytes):
    if len(b) != 32:
        raise ValueError("bad point")
    n = int.from_bytes(b, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    if y >= p:
        raise ValueError("bad point")
    x = _recover_x(y, sign)
    if x is None:
        raise ValueError("bad point")
    P = (x, y, 1, x * y % p)
    if not eq(mul(L, P, reduce=False), ZERO):     # must NOT reduce k mod L here
        raise ValueError("point is not in the prime-order subgroup")
    return P


_By = 4 * pow(5, -1, p) % p
_Bx = _recover_x(_By, 0)
G = (_Bx, _By, 1, _Bx * _By % p)


def _hash_to_point(label: bytes):
    """Nothing-up-my-sleeve point: nobody knows its discrete log with respect to G."""
    ctr = 0
    while True:
        y = int.from_bytes(hashlib.sha512(label + ctr.to_bytes(4, "big")).digest(), "little") % p
        x = _recover_x(y, 0)
        ctr += 1
        if x is None:
            continue
        Q = (x, y, 1, x * y % p)
        for _ in range(3):
            Q = add(Q, Q)                                  # times 8: clears the cofactor
        if not eq(Q, ZERO):
            return Q


H = _hash_to_point(b"sthir-pedersen-H-v1")


class _Fixed:
    """Faster multiplication by a point that never changes (G or H)."""

    def __init__(self, P):
        self.t = [P]
        for _ in range(252):
            self.t.append(add(self.t[-1], self.t[-1]))

    def mul(self, k: int):
        k %= L
        R, i = ZERO, 0
        while k:
            if k & 1:
                R = add(R, self.t[i])
            k >>= 1
            i += 1
        return R


_G, _H = _Fixed(G), _Fixed(H)


def rand_scalar() -> int:
    return secrets.randbelow(L - 1) + 1


def _chal(domain: bytes, *items) -> int:
    h = hashlib.sha512(b"sthir-zk|" + domain)
    for it in items:
        b = compress(it) if isinstance(it, tuple) else bytes(it)
        h.update(len(b).to_bytes(4, "big") + b)
    return int.from_bytes(h.digest(), "little") % L


# ------------------------------------------------------------------ commitments
def commit(v: int, r: int):
    return add(_G.mul(v), _H.mul(r))


# --------------------------------------------------------------------- bit proof
def _bit_prove(bit: int, r: int, C, ctx: bytes):
    """OR-proof that C = r*H (bit 0) or C - G = r*H (bit 1). Returns (c0, c1, s0, s1).
    The branch we do not know is simulated; the one we know uses a real Schnorr response."""
    C0, C1 = C, add(C, neg(G))
    w, cf, sf = rand_scalar(), rand_scalar(), rand_scalar()
    if bit == 0:
        A0, A1 = _H.mul(w), add(_H.mul(sf), neg(mul(cf, C1)))
        c = _chal(b"bit", C, A0, A1, ctx)
        c0 = (c - cf) % L
        return c0, cf, (w + c0 * r) % L, sf
    A1, A0 = _H.mul(w), add(_H.mul(sf), neg(mul(cf, C0)))
    c = _chal(b"bit", C, A0, A1, ctx)
    c1 = (c - cf) % L
    return cf, c1, sf, (w + c1 * r) % L


def _bit_verify(C, proof, ctx: bytes) -> bool:
    c0, c1, s0, s1 = proof
    if not all(0 <= x < L for x in proof):
        return False
    C0, C1 = C, add(C, neg(G))
    A0 = add(_H.mul(s0), neg(mul(c0, C0)))
    A1 = add(_H.mul(s1), neg(mul(c1, C1)))
    return (c0 + c1) % L == _chal(b"bit", C, A0, A1, ctx)


# ------------------------------------------------------------------- range proof
def _hx(n: int) -> str:
    return f"{n:064x}"


def range_prove(v: int, r: int, ctx: bytes = b"") -> dict:
    """Prove that commit(v, r) hides a value in [0, 2^BITS)."""
    if not 0 <= v < 1 << BITS:
        raise ValueError("amount is outside the provable range")
    bits = [(v >> i) & 1 for i in range(BITS)]
    rs = [rand_scalar() for _ in range(BITS - 1)]
    last = (r - sum(rs[i] * (1 << i) for i in range(BITS - 1))) * pow(1 << (BITS - 1), -1, L) % L
    rs.append(last)
    Cs = [commit(bits[i], rs[i]) for i in range(BITS)]
    C = commit(v, r)
    base = ctx + compress(C)
    proofs = [_bit_prove(bits[i], rs[i], Cs[i], base + bytes([i])) for i in range(BITS)]
    return {"C": [compress(c).hex() for c in Cs], "bits": [[_hx(x) for x in pr] for pr in proofs]}


def range_verify(C, proof: dict, ctx: bytes = b"") -> bool:
    try:
        if len(proof["C"]) != BITS or len(proof["bits"]) != BITS:
            return False
        Cs = [decompress(bytes.fromhex(h)) for h in proof["C"]]
        total = ZERO
        for i, c in enumerate(Cs):
            total = add(total, mul(1 << i, c))
        if not eq(total, C):
            return False
        base = ctx + compress(C)
        for i, c in enumerate(Cs):
            pr = tuple(int(x, 16) for x in proof["bits"][i])
            if len(pr) != 4 or not _bit_verify(c, pr, base + bytes([i])):
                return False
        return True
    except (KeyError, ValueError, TypeError):
        return False


# ------------------------------------------------------------------ balance proof
def _balance_prove(excess: int, E, ctx: bytes) -> dict:
    k = rand_scalar()
    R = _H.mul(k)
    c = _chal(b"bal", E, R, ctx)
    return {"R": compress(R).hex(), "s": _hx((k + c * excess) % L)}


def _balance_verify(E, proof: dict, ctx: bytes) -> bool:
    try:
        R, s = decompress(bytes.fromhex(proof["R"])), int(proof["s"], 16)
        if not 0 <= s < L:
            return False
        c = _chal(b"bal", E, R, ctx)
        return eq(_H.mul(s), add(R, mul(c, E)))
    except (KeyError, ValueError, TypeError):
        return False


# --------------------------------------------------------------- a confidential tx
def _tx_ctx(inputs: list[str], outputs: list[str], fee: int) -> bytes:
    return hashlib.sha256(("|".join(inputs) + "#" + "|".join(outputs) + f"#{fee}").encode()).digest()


def build_tx(inputs: list[tuple[int, int]], out_values: list[int], fee: int) -> tuple[dict, list[tuple[int, int]]]:
    """inputs: (value, blinding) of notes you own. Returns (public tx, openings for each output).
    Give each receiver their (value, blinding) over a private channel."""
    if sum(v for v, _ in inputs) != sum(out_values) + fee:
        raise ValueError("inputs must equal outputs plus fee")
    out_r = [rand_scalar() for _ in out_values]
    cin = [compress(commit(v, r)).hex() for v, r in inputs]
    cout = [compress(commit(v, r)).hex() for v, r in zip(out_values, out_r)]
    ctx = _tx_ctx(cin, cout, fee)
    ranges = [range_prove(v, r, ctx + bytes([i])) for i, (v, r) in enumerate(zip(out_values, out_r))]
    excess = (sum(r for _, r in inputs) - sum(out_r)) % L
    E = _excess_point(cin, cout, fee)
    tx = {"inputs": cin, "outputs": [{"C": c, "range": rg} for c, rg in zip(cout, ranges)],
          "fee": fee, "balance": _balance_prove(excess, E, ctx)}
    return tx, list(zip(out_values, out_r))


def _excess_point(cin, cout, fee):
    E = ZERO
    for h in cin:
        E = add(E, decompress(bytes.fromhex(h)))
    for h in cout:
        E = add(E, neg(decompress(bytes.fromhex(h))))
    return add(E, neg(_G.mul(fee)))


def verify_tx(tx: dict) -> tuple[bool, str]:
    """Checks the proofs. That the input notes exist and are unspent is the chain's job."""
    try:
        cin = list(tx["inputs"])
        cout = [o["C"] for o in tx["outputs"]]
        fee = tx["fee"]
        if not (isinstance(fee, int) and 0 <= fee < 1 << BITS) or not cin or not cout:
            return False, "bad shape or fee"
        if len(set(cin)) != len(cin):
            return False, "the same input is listed twice"
        ctx = _tx_ctx(cin, cout, fee)
        for i, o in enumerate(tx["outputs"]):
            if not range_verify(decompress(bytes.fromhex(o["C"])), o["range"], ctx + bytes([i])):
                return False, f"output {i} has no valid range proof"
        if not _balance_verify(_excess_point(cin, cout, fee), tx["balance"], ctx):
            return False, "inputs do not equal outputs plus fee"
    except (KeyError, ValueError, TypeError):
        return False, "malformed transaction"
    return True, "ok"


def open_note(C_hex: str, v: int, r: int) -> bool:
    """What a receiver does with the (value, blinding) it was handed."""
    return eq(decompress(bytes.fromhex(C_hex)), commit(v, r))


# ------------------------------------------------------------------------- demo
def demo() -> None:
    import json
    import time
    UNIT = 100
    print("Alice owns one hidden note of 100.00. She pays Bob 30.00, keeps 69.50 as change, fee 0.50.")
    inp = [(100 * UNIT, rand_scalar())]
    t = time.time()
    tx, openings = build_tx(inp, [30 * UNIT, 69 * UNIT + 50], 50)
    tb = time.time() - t
    t = time.time()
    ok, why = verify_tx(tx)
    tv = time.time() - t
    size = len(json.dumps(tx))
    print(f"  build {tb:.2f}s, verify {tv:.2f}s, size {size / 1024:.1f} KB")
    print(f"  anyone verifies:  {ok} ({why}).  What the verifier sees: points like {tx['outputs'][0]['C'][:20]}... never an amount.")
    print(f"  Bob opens his note: {open_note(tx['outputs'][0]['C'], *openings[0])}   with a wrong amount: {open_note(tx['outputs'][0]['C'], 31 * UNIT, openings[0][1])}")

    print("\nAttacks:")
    try:
        build_tx(inp, [60 * UNIT, 60 * UNIT], 0)
    except ValueError as e:
        print("  honest builder refuses to create coins:", e)
    cheat, _ = build_tx([(100 * UNIT, inp[0][1])], [30 * UNIT, 69 * UNIT + 50], 50)
    import copy
    forged = copy.deepcopy(cheat)
    forged["fee"] = 0                                          # claim a smaller fee: coins appear
    print("  change the fee after proving:", verify_tx(forged))
    forged = copy.deepcopy(cheat)
    forged["outputs"][0]["range"]["bits"][3][2] = "0" * 63 + "1"   # damage one bit proof
    print("  damage one range proof:", verify_tx(forged))
    try:
        range_prove(-5 % L, rand_scalar())
    except ValueError as e:
        print("  prove a 'negative' amount (wraps to a huge number):", e)


if __name__ == "__main__":
    demo()
