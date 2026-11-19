# Architecture and honest feasibility

Written for engineers and reviewers. Each feature is marked **built**, **research** or **not possible as stated**.

## Status of the original goals

| Goal | Status | Notes |
|---|---|---|
| Phone node in Python | built | Runs under Termux; SQLite/JSON persistence with re-validation. |
| Offline payments | built (module) | Voucher + Cap, below. The lock is not yet a chain rule. |
| Verifying heavy compute cheaply | built (toy) | Spot check plus dispute, below. Not zero knowledge. |
| Confidential amounts | built (module) | Pedersen + range + balance proofs. Unaudited. |
| Lattice signatures | research | ML-DSA slot exists (`oqs` package); not bundled. Ed25519 is used. |
| DAG ledger with instant finality | research | Parallel blocks work (Kaspa). Finality needs a vote layer. |
| Useful compute as the block lottery | not possible as stated | No difficulty knob, predictable, costly to check. Use a task market beside a normal lottery. |
| ZK proof of arbitrary heavy compute | research | Proving costs 1,000x to 1,000,000x the computation. Not for phones. |
| CRDTs preventing double spends | not possible as stated | CRDTs merge both spends. Use vouchers. CRDTs only for non-financial data. |
| Bridge-less cross-chain swaps | not possible as stated | Every design trusts a light client, a validator set or a timelock. |
| Autonomous AI upgrades | not possible as stated | AI may propose and analyse; humans must approve with a time lock. |

## Voucher + Cap (offline payments)

1. **Lock (online).** An owner asks a hub to lock `count x value` coins plus a bond (25%). The hub signs an attestation.
2. **Spend (offline).** The owner signs one numbered voucher to the receiver. The receiver checks the attestation, the signature, the expiry, its own per-sale limit, and that the number was not already seen. No network needed.
3. **Redeem (online).** The hub pays each `(book, number)` once. A second redemption of the same number to a different receiver is fraud: the owner is banned, the bond is forfeited, and the later receiver is paid from the bond and then the unspent lock.
4. **Close.** After expiry plus a one-day grace, the unspent lock returns to the owner.

States: book `LOCKED -> CLOSED | SLASHED`; voucher `UNUSED -> ACCEPTED (offline) -> REDEEMED | REJECTED`.

Guarantees: total payable from one book never exceeds what was locked. Not guaranteed: two offline receivers can both accept the same number; the loss is bounded by the bond plus unspent lock, so shops should cap each sale. The lock is held by the hub's own ledger; making `lock` and `redeem` chain transactions is a consensus upgrade that is not done.

## Verifiable compute (`sthir_verify.py`)

A heavy node runs `N` deterministic steps, hashes every state into a Merkle tree and publishes `(seed, N, root, final)`.

- **Spot check (phone).** Choose `k` step indexes from a hash of the claim. The prover opens the two states around each step; the phone re-runs those `k` steps. Cost: `k` steps and `2k log2 N` hashes instead of `N` steps. If a fraction `f` of steps are wrong the cheat is caught with probability `1 - (1 - f)^k`. **One** wrong step is caught only with probability `k/N` (measured: 3.3% for `N=512`, `k=16`).
- **Dispute.** Anyone who re-runs the task and sees a different final state bisects the trace with the prover in `log2 N` rounds down to one step; the phone re-runs that single step and decides. This catches a single wrong step, provided at least one honest challenger exists and has a bond to lose.

This is the optimistic-rollup idea, not a SNARK. A real workload needs a step function with a small, exactly reproducible state.

## Confidential amounts (`sthir_zk.py`)

Pedersen commitments `C = vG + rH`. A range proof shows `v` is in `[0, 2^32)` using one commitment and one OR-proof per bit. A balance proof (Schnorr over `H`) shows inputs equal outputs plus fee. Together they stop coin creation and "negative" amounts without revealing values. Missing for a private chain: note encryption to the receiver, nullifiers against double spends, and consensus rules.

## Roadmap

1. Make `lock` and `redeem` chain transactions (consensus upgrade, with a migration plan).
2. Task market on the chain (direct and replicated verification).
3. ML-DSA signatures where `oqs` is available.
4. DAG ordering and checkpoint finality, simulated first.
5. Independent security review before any real-value use.
