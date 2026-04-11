#!/usr/bin/env python3
"""
T6 — Small concrete instance of Theorem 3.9.1
================================================

QANARY v3.0 paper, §3.9.4 (Theorem 3.9.1: value-independence ⇒
first-order distributional security).

Statement
---------
For a toy modulus q = 5, share width w = 3 bits, fresh randomness
r ∈ {0,1}^2, and the arithmetic masking relation
              s0 = URem(x − s1 + q, q),
this script enumerates ALL (x, s1, r) assignments and machine-checks
two facts that together demonstrate Theorem 3.9.1 and its converse:

  (Case A — Theorem holds, sufficient direction)
    A wire function w_A(s0, s1, r) := bit0(s1)
    is **value-independent of x** in the sense of Definition 3
    (it does not depend on s0 at all). The marginal Pr[w_A = 1 | x]
    is constant in x — exactly as Theorem 3.9.1 predicts.

  (Case B — converse fails: SADC is sufficient but not tight)
    A wire function w_B(s0, s1, r) := bit0(s0)
    is **NOT value-independent of x** (its value at fixed s1 changes
    when x changes, since s0 changes). Yet its marginal Pr[w_B = 1 | x]
    is also constant in x, because s0 is uniform on Z_q whenever s1 is.
    This is the canonical "threshold rebalancing" example from §3.9.4
    and explains why arithmetic SADC labels such wires
    INSECURE_CONSERVATIVE rather than INSECURE: the test catches
    everything Theorem 3.9.1 flags but is intentionally not tight.

Both facts are checked two ways:
  1. Pure-Python enumeration of the joint distribution.
  2. Z3 symbolic check of the value-independence predicate over the
     same toy domain.

Theory
------
Z3 QF_BV. Toy modulus is small enough that the full domain
(5 × 5 × 4 = 100 assignments) fits trivially in any solver.

Why a small instance?
---------------------
T1 (the universal version of Theorem 3.9.1) is the hard one. T6
demonstrates the same theorem mechanically on a small instance, which
is robust against subtle formalization errors and gives the reader a
worked example of the proof's structure.
"""

import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import z3

sys.path.insert(0, str(Path(__file__).parent))
from _proof_utils import cvc5_check_smtlib  # noqa: E402

Q = 5         # toy modulus
W = 3         # share width in bits (5 < 2^3 = 8)
R_BITS = 2    # fresh randomness width


def s0_of(x: int, s1: int) -> int:
    """Wraparound-safe arithmetic mask, matching sadc_arith.py."""
    return (x - s1 + Q) % Q


def wire_A(s0: int, s1: int, r: int) -> int:
    """Case A: depends only on s1 — value-independent of x."""
    return s1 & 1


def wire_B(s0: int, s1: int, r: int) -> int:
    """Case B: depends on s0 — NOT value-independent, yet distributionally fine."""
    return s0 & 1


def enumerate_marginal(wire) -> dict[int, dict[int, float]]:
    """Return Pr[w = v | x] for v ∈ {0, 1}, x ∈ Z_q, marginal over (s1, r)."""
    n_inner = Q * (1 << R_BITS)
    out: dict[int, dict[int, float]] = {}
    for x in range(Q):
        cnt: Counter[int] = Counter()
        for s1 in range(Q):
            s0 = s0_of(x, s1)
            for r in range(1 << R_BITS):
                cnt[wire(s0, s1, r)] += 1
        out[x] = {v: cnt.get(v, 0) / n_inner for v in (0, 1)}
    return out


def is_marginal_constant(margs: dict[int, dict[int, float]]) -> bool:
    base = margs[0]
    return all(margs[x] == base for x in margs)


def check_value_independence_python(wire) -> tuple[bool, str]:
    """Pointwise check: ∀ x, x', s1, r: w(s0(x), s1, r) == w(s0(x'), s1, r)."""
    for x in range(Q):
        for x_prime in range(Q):
            for s1 in range(Q):
                s0 = s0_of(x, s1)
                s0p = s0_of(x_prime, s1)
                for r in range(1 << R_BITS):
                    if wire(s0, s1, r) != wire(s0p, s1, r):
                        cex = f"x={x},x'={x_prime},s1={s1},r={r}"
                        return False, cex
    return True, ""


def build_vi_solver(use_s0_in_wire: bool) -> z3.Solver:
    """Z3 encoding of value-independence as a counterexample search.

    use_s0_in_wire=False ⇒ wire = bit0(s1)         (Case A: VI)
    use_s0_in_wire=True  ⇒ wire = bit0(s0)         (Case B: not VI)

    Note on fresh randomness r: the Theorem 3.9.1 statement quantifies
    over uniform r, but Cases A and B are both purely functions of
    (s0, s1) — r is irrelevant to the SMT obligation. Per the bridging
    argument in T1's docstring, dropping r from this encoding is sound
    because r-marginalization preserves the conclusion under (A3)/(A4).
    The Python enumeration above (`enumerate_marginal`) does iterate
    over r ∈ {0,1}^2 explicitly to mirror the Theorem 3.9.1 setup.
    """
    x = z3.BitVec("x", W)
    xp = z3.BitVec("xp", W)
    s1 = z3.BitVec("s1", W)
    q = z3.BitVecVal(Q, W)

    solver = z3.Solver()
    solver.set("random_seed", 0)
    solver.add(z3.ULT(x, q))
    solver.add(z3.ULT(xp, q))
    solver.add(z3.ULT(s1, q))

    s0 = z3.URem(x - s1 + q, q)
    s0p = z3.URem(xp - s1 + q, q)

    if use_s0_in_wire:
        w = z3.Extract(0, 0, s0)
        wp = z3.Extract(0, 0, s0p)
    else:
        w = z3.Extract(0, 0, s1)
        wp = z3.Extract(0, 0, s1)

    solver.add(x != xp)
    solver.add(w != wp)  # counterexample to value-independence
    return solver


def main() -> int:
    print("=" * 70)
    print("T6 — Small concrete instance of Theorem 3.9.1")
    print(f"  q = {Q}   w = {W} bits   r = {R_BITS} bits")
    print(f"  domain size: |Z_q|^2 × |r| = {Q * Q * (1 << R_BITS)}")
    print("=" * 70)

    all_ok = True

    for label, wire, expect_vi in (
        ("A: w = bit0(s1)  (value-independent)", wire_A, True),
        ("B: w = bit0(s0)  (NOT value-independent, distributionally OK)", wire_B, False),
    ):
        print()
        print(f"  Case {label}")

        # 1. Marginal distribution
        marg = enumerate_marginal(wire)
        marg_const = is_marginal_constant(marg)
        for x in range(Q):
            ones = marg[x][1]
            print(f"      Pr[w=1 | x={x}] = {ones:.4f}")
        print(f"      marginal constant in x: {marg_const}")

        # 2. Value-independence (pure-Python pointwise)
        vi_py, cex = check_value_independence_python(wire)
        print(f"      value-independent (Python pointwise): {vi_py}"
              + (f"   counterexample: {cex}" if not vi_py else ""))

        # 3. Z3 value-independence check
        use_s0 = wire is wire_B
        solver = build_vi_solver(use_s0_in_wire=use_s0)
        t0 = time.perf_counter()
        z3_result = str(solver.check())
        z3_ms = (time.perf_counter() - t0) * 1000
        print(f"      Z3 VI counterexample search: {z3_result}  ({z3_ms:.2f} ms)")

        # 4. CVC5 cross-check
        cvc5_result, cvc5_ms = cvc5_check_smtlib(solver.to_smt2())
        print(f"      CVC5 VI counterexample search: {cvc5_result}  ({cvc5_ms:.2f} ms)")

        # Expected: Case A → unsat (VI), Case B → sat (not VI)
        if expect_vi:
            ok = vi_py and z3_result == "unsat" and (
                cvc5_result == "unsat" or cvc5_result.startswith("skipped")
            ) and marg_const
        else:
            ok = (not vi_py) and z3_result == "sat" and (
                cvc5_result == "sat" or cvc5_result.startswith("skipped")
            ) and marg_const

        print(f"      Case verdict: {'PROVED as expected' if ok else 'FAILED'}")
        all_ok = all_ok and ok

    print()
    if all_ok:
        print("  STATUS: T6 PROVED")
        print("    (Case A) value-independence ⇒ marginal constant       — Theorem 3.9.1")
        print("    (Case B) marginal constant does NOT imply VI          — converse fails")
        return 0
    print("  STATUS: T6 FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
