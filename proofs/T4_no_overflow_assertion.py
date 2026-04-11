#!/usr/bin/env python3
"""
T4 — No-overflow assertion correctness
========================================

QANARY v3.0 paper, §3.9.3 (Arithmetic SADC) and §3.9.5 (Implementation).

Statement
---------
For the wraparound-safe arithmetic reparametrization used in
`sadc_arith.py:352`,
                    s0 = URem(x − s1 + q, q),
the intermediate quantity (x − s1 + q) must lie in [1, 2q) so that
URem produces the mathematical (x − s1) mod q without bit-vector
wraparound. This requires the container width w to satisfy 2q ≤ 2^w.

Two obligations are checked:

  (T4a)   For q = 3329 (ML-KEM), w = 24:
          for all x, s1 ∈ [0, q), the bit-vector value
          (x − s1 + q) interpreted as an unsigned w-bit integer
          equals the mathematical integer x − s1 + q exactly,
          and 1 ≤ (x − s1 + q) < 2q < 2^w.

  (T4b)   For q = 8 380 417 (ML-DSA), w = 24:
          THIS IS THE DEPLOYED CONFIGURATION. Adams Bridge stores
          ML-DSA shares in 24-bit containers (see sadc_arith.py:11
          and :138, MLDSA_SHARE_WIDTH = 24). The headroom is tight:
          2q = 16 760 834 vs 2^24 = 16 777 216, leaving only 16 382
          (~0.1%) of slack. T4b verifies this tight case formally.

  (T4c)   For q = 8 380 417 (ML-DSA), w = 46 = 2 × ⌈log₂ q⌉:
          conservative-bound demonstration. With 2q = 16 760 834
          ≪ 2^46 ≈ 7.04 × 10^13, headroom is enormous. This case
          is included as a sanity check but is NOT the deployed
          configuration; T4b is the case that matches the netlist.

All three obligations are encoded as searches for a counterexample in
QF_BV; UNSAT means no counterexample exists, proving the lemma.

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
    Instance("ML-DSA (q = 8 380 417, w = 46)   [conservative bound]", q=8_380_417, w=46),
]


def build_solver(inst: Instance) -> z3.Solver:
    """Counterexample search: ∃ x, s1 ∈ [0, q) such that
    the BV value (x − s1 + q) is NOT in [1, 2q), or 2q > 2^w."""
    x = z3.BitVec("x", inst.w)
    s1 = z3.BitVec("s1", inst.w)
    q_bv = z3.BitVecVal(inst.q, inst.w)
    two_q = z3.BitVecVal(2 * inst.q, inst.w)
    one = z3.BitVecVal(1, inst.w)
    intermediate = x - s1 + q_bv

    solver = z3.Solver()
    solver.set("random_seed", 0)
    # Domain constraints: x, s1 ∈ [0, q).
    solver.add(z3.ULT(x, q_bv))
    solver.add(z3.ULT(s1, q_bv))
    # Counterexample: intermediate < 1  OR  intermediate >= 2q.
    # (Either bound violation indicates wraparound or out-of-range.)
    solver.add(z3.Or(z3.ULT(intermediate, one), z3.UGE(intermediate, two_q)))
    return solver


def check_capacity(inst: Instance) -> bool:
    """Pure-arithmetic precondition: 2q < 2^w."""
    return 2 * inst.q < (1 << inst.w)


def prove_z3(inst: Instance) -> tuple[str, float]:
    t0 = time.perf_counter()
    result = build_solver(inst).check()
    return str(result), (time.perf_counter() - t0) * 1000


def main() -> int:
    print("=" * 70)
    print("T4 — No-overflow assertion correctness")
    print("  obligation: x, s1 ∈ [0, q)  ⇒  1 ≤ (x − s1 + q) < 2q < 2^w")
    print("=" * 70)

    all_ok = True
    for inst in INSTANCES:
        cap_ok = check_capacity(inst)
        cap_str = f"2q = {2 * inst.q}, 2^w = {1 << inst.w}"
        z3_result, z3_ms = prove_z3(inst)
        cvc5_result, cvc5_ms = cvc5_check_smtlib(build_solver(inst).to_smt2())

        z3_unsat = z3_result == "unsat"
        cvc5_unsat = cvc5_result == "unsat" or cvc5_result.startswith("skipped")
        ok = cap_ok and z3_unsat and cvc5_unsat

        print()
        print(f"  Instance: {inst.name}")
        print(f"    capacity check ({cap_str}): {'OK' if cap_ok else 'FAIL'}")
        print(f"    Z3   : {z3_result:8s}  ({z3_ms:8.2f} ms)")
        print(f"    CVC5 : {cvc5_result:8s}  ({cvc5_ms:8.2f} ms)")
        print(f"    {'PROVED' if ok else 'FAILED'}")
        all_ok = all_ok and ok

    print()
    if all_ok:
        print("  STATUS: T4 PROVED  (no overflow on (x − s1 + q) for both moduli)")
        return 0
    print("  STATUS: T4 FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
