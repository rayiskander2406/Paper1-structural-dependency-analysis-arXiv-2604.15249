#!/usr/bin/env python3
"""
T2 — Boolean reparametrization round-trip lemma
================================================

QANARY v3.0 paper, §3.9.2 (Boolean SADC) and Definition 3 (§3.9.4).

Statement
---------
For any x, s1 ∈ {0,1}^k, defining s0 = x XOR s1, prove that
                    s0 XOR s1 = x.

This is the soundness check for the Boolean reparametrization step that
SADC uses to substitute the symbolic secret X into the wire expression
in place of (s0, s1).

Theory
------
QF_BV (quantifier-free bit-vectors). The lemma is universally quantified
in the meta-theory but encodable as a UNSAT proof in QF_BV: we ask the
solver to find ANY (x, s1) such that (x XOR s1) XOR s1 != x. UNSAT means
no such counterexample exists, which proves the lemma for the chosen
width k.

Solvers
-------
Z3 (primary, via Python API) and CVC5 (cross-check, via SMT-LIB2 dump).

Width
-----
k = 24 — matches the share width used in the Adams Bridge ML-KEM Barrett
module (2 × MLKEM_Q_WIDTH = 24 bits). The lemma holds for any width;
we pin k = 24 to match the deployed configuration.
"""

import sys
import time
from pathlib import Path

import z3

sys.path.insert(0, str(Path(__file__).parent))
from _proof_utils import cvc5_check_smtlib  # noqa: E402

K = 24  # share width in bits (2 × MLKEM_Q_WIDTH)


def build_solver() -> z3.Solver:
    x = z3.BitVec("x", K)
    s1 = z3.BitVec("s1", K)
    s0 = x ^ s1
    solver = z3.Solver()
    solver.set("random_seed", 0)
    # Search for a counterexample to (s0 XOR s1) == x.
    solver.add((s0 ^ s1) != x)
    return solver


def prove_z3() -> tuple[str, float]:
    t0 = time.perf_counter()
    result = build_solver().check()
    return str(result), (time.perf_counter() - t0) * 1000


def main() -> int:
    print("=" * 70)
    print("T2 — Boolean reparametrization round-trip")
    print(f"  k = {K} bits   theory = QF_BV")
    print("=" * 70)

    # Z3 proof
    z3_result, z3_ms = prove_z3()
    print(f"  Z3   : {z3_result:8s}  ({z3_ms:6.2f} ms)")

    # CVC5 cross-check via SMT-LIB2 export
    cvc5_result, cvc5_ms = cvc5_check_smtlib(build_solver().to_smt2())
    print(f"  CVC5 : {cvc5_result:8s}  ({cvc5_ms:6.2f} ms)")

    z3_unsat = z3_result == "unsat"
    cvc5_unsat = cvc5_result == "unsat" or cvc5_result.startswith("skipped")
    if z3_unsat and cvc5_unsat:
        print("  STATUS: T2 PROVED  (Boolean round-trip holds)")
        return 0
    print("  STATUS: T2 FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
