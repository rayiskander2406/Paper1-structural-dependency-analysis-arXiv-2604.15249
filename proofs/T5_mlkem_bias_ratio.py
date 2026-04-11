#!/usr/bin/env python3
"""
T5 — ML-KEM raw-RNG bias ratio
================================

QANARY v3.0 paper, §6 Limitation L9 (mask uniformity scope).

Statement
---------
A 12-bit RNG produces uniform values on {0, 1, ..., 4095}. When these
values are reduced modulo q = 3329 to feed Z_q-valued masks (the naive
"raw RNG" path), the resulting distribution on Z_q is non-uniform:

  • residues 0 ≤ r ≤ 766 receive probability 2 / 4096 each,
  • residues 767 ≤ r ≤ 3328 receive probability 1 / 4096 each.

The maximum bias ratio is exactly 2.

This number anchors the L9 ("mask uniformity") caveat in §6: if a
deployer uses raw 12-bit RNG without rejection sampling or two-draw
mixing, the mask is biased by at most 2× per residue, and Theorem
3.9.1 (assumption A2: mask uniform on Z_q) is violated.

Implementation
--------------
Pure-Python exhaustive enumeration is the canonical proof: we iterate
over every 12-bit value v ∈ [0, 4096), tally counts[v % q], and check
the resulting distribution against the closed-form bound. No SMT is
needed because the domain is finite and small (4096 values).

We additionally run a Z3 *self-consistency check* of the closed-form
predicate ⌈(4096 − r) / q⌉ against itself: for every residue r, the
predicate "r + expected*q ≥ N AND r + (expected − 1)*q < N" with
expected = ITE(r < 767, 2, 1) holds. This is NOT an independent proof
of the count — it is a redundancy check that the closed form is
internally consistent and that the boundary value 767 is correct.
The pure-Python enumeration is the load-bearing artifact; Z3 and CVC5
serve as cross-checks against transcription error in the closed form.
"""

import sys
import time
from pathlib import Path

import z3

sys.path.insert(0, str(Path(__file__).parent))
from _proof_utils import cvc5_check_smtlib  # noqa: E402

Q = 3329
K = 12
N = 1 << K  # 4096


def enumerate_distribution() -> list[int]:
    counts = [0] * Q
    for v in range(N):
        counts[v % Q] += 1
    return counts


def closed_form_count(r: int) -> int:
    """Number of 12-bit values in [0, 4096) congruent to r mod q."""
    return (N - 1 - r) // Q + 1


def verify_with_z3() -> tuple[str, float]:
    """Z3 self-consistency check (NOT an independent proof of the count).

    Verifies that for every residue r ∈ [0, q), the closed-form
    predicate "expected = ITE(r < boundary, 2, 1) AND
    r + expected*q ≥ N AND r + (expected − 1)*q < N" is internally
    consistent. This is a redundancy check that the closed form is
    well-formed and that boundary = N − q = 767 is correct; the
    canonical proof of the count is the pure-Python enumeration above.
    """
    t0 = time.perf_counter()
    boundary = N - Q  # 767
    solver = z3.Solver()
    solver.set("random_seed", 0)
    r = z3.Int("r")
    solver.add(0 <= r, r < Q)
    # Closed-form predicate
    expected = z3.If(r < boundary, 2, 1)
    # Direct counting predicate using existential v's:
    # there are exactly `expected` values v ∈ [0, N) with v ≡ r mod q.
    # Equivalent: r + expected*q ≥ N AND r + (expected − 1)*q < N
    # i.e., the next multiple lands beyond N.
    counter = z3.And(
        r + expected * Q >= N,
        r + (expected - 1) * Q < N,
    )
    solver.add(z3.Not(counter))
    result = solver.check()
    return str(result), (time.perf_counter() - t0) * 1000


def main() -> int:
    print("=" * 70)
    print("T5 — ML-KEM raw-RNG bias ratio")
    print(f"  q = {Q}   k = {K}   N = {N}")
    print("=" * 70)

    counts = enumerate_distribution()
    boundary = N - Q  # 767
    sum_counts = sum(counts)
    max_count, min_count = max(counts), min(counts)
    ratio = max_count // min_count

    closed_form_ok = all(counts[r] == closed_form_count(r) for r in range(Q))
    low_block_ok = counts[:boundary] == [2] * boundary
    high_block_ok = counts[boundary:] == [1] * (Q - boundary)

    print(f"  enum: residues 0..{boundary - 1}        → count = 2 each: {low_block_ok}")
    print(f"  enum: residues {boundary}..{Q - 1}    → count = 1 each: {high_block_ok}")
    print(f"  enum: max count = {max_count}, min count = {min_count}, ratio = {ratio}")
    print(f"  enum: Σ counts = {sum_counts} (expected {N}: {sum_counts == N})")
    print(f"  enum: closed-form ⌈(N − r)/q⌉ matches every residue: {closed_form_ok}")

    z3_result, z3_ms = verify_with_z3()
    print(f"  Z3 self-consistency check (closed form):  "
          f"{z3_result:8s}  ({z3_ms:8.2f} ms)")

    cvc5_result, cvc5_ms = cvc5_check_smtlib(_build_z3_solver_for_export())
    print(f"  CVC5 self-consistency check (closed form): "
          f"{cvc5_result:8s}  ({cvc5_ms:8.2f} ms)")

    z3_unsat = z3_result == "unsat"
    cvc5_unsat = cvc5_result == "unsat" or cvc5_result.startswith("skipped")
    pure_python_ok = (
        sum_counts == N
        and ratio == 2
        and low_block_ok
        and high_block_ok
        and closed_form_ok
    )
    if pure_python_ok and z3_unsat and cvc5_unsat:
        print("  STATUS: T5 PROVED  (max bias ratio = 2 for raw 12-bit → Z_3329)")
        return 0
    print("  STATUS: T5 FAILED")
    return 1


def _build_z3_solver_for_export() -> str:
    boundary = N - Q
    solver = z3.Solver()
    r = z3.Int("r")
    solver.add(0 <= r, r < Q)
    expected = z3.If(r < boundary, 2, 1)
    counter = z3.And(
        r + expected * Q >= N,
        r + (expected - 1) * Q < N,
    )
    solver.add(z3.Not(counter))
    return solver.to_smt2()


if __name__ == "__main__":
    sys.exit(main())
