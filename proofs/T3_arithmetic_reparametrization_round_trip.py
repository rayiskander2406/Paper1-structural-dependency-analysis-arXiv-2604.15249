#!/usr/bin/env python3
"""
T3 — Arithmetic reparametrization round-trip lemma
====================================================

QANARY v3.0 paper, §3.9.3 (Arithmetic SADC) and Definition 3 (§3.9.4).

Statement
---------
For any x, s1 ∈ [0, q-1] and the wraparound-safe encoding used in
`sadc_arith.py:352`,
                    s0 = URem(x − s1 + q, q),
prove that
                    URem(s0 + s1, q) = x.

This is the soundness check for the arithmetic reparametrization step
that the arithmetic SADC pass uses to substitute the symbolic secret X
into the wire expression in place of (s0, s1). It is intentionally
formulated to match the EXACT bit-vector encoding used by the
implementation (rather than the mathematical (x − s1) mod q), because
the bit-vector subtract wraps when x < s1; sadc_arith.py adds q before
the URem to keep the intermediate value in [1, 2q) ⊂ [0, 2^w).

Theory
------
QF_BV with URem. The proof obligation is encoded as a search for a
counterexample (x, s1) in [0, q) × [0, q) such that
URem(URem(x − s1 + q, q) + s1, q) ≠ x. UNSAT means no such
counterexample exists, which proves the lemma.

Deployed configurations
-----------------------
Per `sadc_arith.py:10-11` and `:138`, Adams Bridge stores BOTH ML-KEM
and ML-DSA shares in 24-bit containers. T3 verifies both:

  T3a — ML-KEM: q = 3329,    w = 24 (= 2 × MLKEM_Q_WIDTH)
  T3b — ML-DSA: q = 8380417, w = 24 (1-bit slack over the 23-bit modulus)

Both rely on the no-overflow precondition `2q < 2^w` verified by T4.
The ML-DSA case is tight: 2q = 16,760,834 vs 2^24 = 16,777,216
(headroom 16,382 ≈ 0.1%).

Solvers
-------
Z3 (primary) and CVC5 (cross-check via SMT-LIB2 export).
"""

import sys
import time
from dataclasses import dataclass
from pathlib import Path

import z3

sys.path.insert(0, str(Path(__file__).parent))
from _proof_utils import cvc5_check_smtlib  # noqa: E402


@dataclass
class Instance:
    name: str
    q: int
    w: int


INSTANCES = [
    Instance("ML-KEM (q = 3329, w = 24)        [deployed]", q=3329, w=24),
    Instance("ML-DSA (q = 8 380 417, w = 24)   [deployed, tight]", q=8_380_417, w=24),
]


def build_solver(inst: Instance) -> z3.Solver:
    x = z3.BitVec("x", inst.w)
    s1 = z3.BitVec("s1", inst.w)
    q = z3.BitVecVal(inst.q, inst.w)
    # Wraparound-safe formula matching sadc_arith.py:352
    #   s0 = URem(X − S1 + q, q)
    s0 = z3.URem(x - s1 + q, q)
    round_trip = z3.URem(s0 + s1, q)

    solver = z3.Solver()
    solver.set("random_seed", 0)
    # Domain constraints: x, s1 ∈ [0, q).
    solver.add(z3.ULT(x, q))
    solver.add(z3.ULT(s1, q))
    # Search for a counterexample to round_trip == x.
    solver.add(round_trip != x)
    return solver


def prove_z3(inst: Instance) -> tuple[str, float]:
    t0 = time.perf_counter()
    result = build_solver(inst).check()
    return str(result), (time.perf_counter() - t0) * 1000


def main() -> int:
    print("=" * 70)
    print("T3 — Arithmetic reparametrization round-trip")
    print("  obligation: URem(URem(x − s1 + q, q) + s1, q) = x")
    print("  theory: QF_BV (URem)")
    print("=" * 70)

    all_ok = True
    for inst in INSTANCES:
        z3_result, z3_ms = prove_z3(inst)
        cvc5_result, cvc5_ms = cvc5_check_smtlib(build_solver(inst).to_smt2())

        z3_unsat = z3_result == "unsat"
        cvc5_unsat = cvc5_result == "unsat" or cvc5_result.startswith("skipped")
        ok = z3_unsat and cvc5_unsat

        print()
        print(f"  Instance: {inst.name}")
        print(f"    Z3   : {z3_result:8s}  ({z3_ms:8.2f} ms)")
        print(f"    CVC5 : {cvc5_result:8s}  ({cvc5_ms:8.2f} ms)")
        print(f"    {'PROVED' if ok else 'FAILED'}")
        all_ok = all_ok and ok

    print()
    if all_ok:
        print("  STATUS: T3 PROVED  (arithmetic round-trip holds for both deployed moduli)")
        return 0
    print("  STATUS: T3 FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
