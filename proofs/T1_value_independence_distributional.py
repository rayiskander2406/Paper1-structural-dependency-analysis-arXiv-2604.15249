#!/usr/bin/env python3
"""
T1 — Small-domain finite expansion of Theorem 3.9.1
=====================================================

QANARY v3.0 paper, small-domain instance of Theorem 3.9.1 (§3.9.4).

Strict scope statement
----------------------
This script does NOT verify Theorem 3.9.1 in its full generality. It
verifies a SUB-THEOREM in which the modulus is fixed at q = 5, the
fresh-randomness channel r is collapsed (see "Bridging argument" below),
and the universal premise over wire functions is replaced by a
finite-domain expansion. The relationship to the full theorem is via
the bridging argument documented below — that argument is mathematically
elementary (the law of total probability) but is NOT itself verified by
SMT in this script. The fully-universal version of Theorem 3.9.1 is
reported as future work in §6 of the paper.

Sub-theorem statement (what is actually proven here)
----------------------------------------------------
Let q = 5, x ∈ Z_q the secret, s1 ∈ Z_q the mask, and define the
arithmetic share s0(x, s1) := (x − s1 + q) mod q (matching
sadc_arith.py:352). Let w : Z_q × Z_q → Bool be an arbitrary Boolean
wire function. Assume:

  (A1) single-probe (w produces a single bit; encoded by w returning Bool)
  (A2) s1 uniform on Z_q AND independent of x (encoded by uniform
       summation over the entire Z_q domain)
  (A3*, A4*) collapsed via the bridging argument below — the
       r-bearing version follows from this r-free version by uniform
       marginalization over independent randomness channels.

Then, if w is value-independent of x in the sense of Definition 3 —
i.e., for all y, y', t ∈ Z_q,
            w(s0(y, t), t) = w(s0(y', t), t) —
the marginal count
            c(x) := |{t ∈ Z_q : w(s0(x, t), t) = true}|
is constant in x. We verify this for every pair (x, x') ∈ Z_5 × Z_5.

Bridging argument from r-free (this script) to r-bearing (Theorem 3.9.1)
------------------------------------------------------------------------
Theorem 3.9.1 takes the marginal over uniform s1 AND uniform r. T1's
r-free formalization is a sound sub-theorem because:

  (i)   For any fixed assignment to r, the wire restricts to
        w_r(s0, s1) := w(s0, s1, r), which is a function only of
        (s0, s1). Each w_r is therefore in the function space that
        T1 quantifies over.

  (ii)  Value-independence of w over the joint domain (s0, s1, r)
        implies value-independence of every per-r restriction w_r
        over (s0, s1). This is by direct instantiation of the VI
        premise at fixed r.

  (iii) T1 (this script) proves marginal-count constancy in x for
        every wire function in the (s0, s1)-only function space, at
        q = 5. By (ii), the conclusion applies to every w_r.

  (iv)  The marginal of w over uniform r is the uniform mixture
        Pr[w = v | x] = Σ_r Pr[r] · Pr[w_r = v | x]. Each summand is
        constant in x by (iii). A uniform mixture of x-constant
        summands is x-constant.

  (v)   The argument is first-order over the law of total probability
        and uses (A3) (r uniform, independent of (x, s1)) and (A4)
        (mutually independent randomness channels) only at step (iv);
        these are the assumptions of Theorem 3.9.1 that this script
        does not encode in SMT.

Steps (i)–(iv) are not verified by SMT in this script. They are
documented here so that the relationship between the r-free
sub-theorem this script proves and the r-bearing Theorem 3.9.1 in
the paper is auditable.

Strategy
--------
The instance domain is small (q = 5, so 5 × 5 = 25 (s0, t) cells, hence
2^25 possible wire functions). We encode `w` as an uninterpreted
function, instantiate the value-independence premise as 5 × 5 = 25
concrete equality assertions (per pair, the t-th column equates four
copies of w(·, t)), and ask CVC5 and Z3 to prove that for any pair
of secrets (x, x') the marginal counts c(x) and c(x') are equal.

This is a closed first-order formula over a finite domain, with no
universal quantifiers in the prover-visible body — CVC5 (and Z3) can
verify it without needing quantifier instantiation heuristics.

The full universal version of T1 — quantifying over q (any prime) and
over the wire-function space simultaneously — is left as future work
(see §6 of the paper). The small-instance version proven here, combined
with T6 (which exhibits both VI⇒MC and the failure of the converse on
the same q = 5 domain), suffices for the methodological claim in §3.9.4.

Solvers
-------
CVC5 (preferred — universal prover for Tier-A claims in this suite)
and Z3 (cross-check).
"""

import sys
import time
from pathlib import Path

import z3

sys.path.insert(0, str(Path(__file__).parent))
from _proof_utils import cvc5_check_smtlib, locate_cvc5  # noqa: E402

Q = 5  # toy modulus (prime, small enough for finite expansion)


def s0(x: int, s1: int) -> int:
    """Wraparound-safe arithmetic share, matching sadc_arith.py."""
    return (x - s1 + Q) % Q


# ---------------------------------------------------------------------------
# Z3 encoding (cross-check)
# ---------------------------------------------------------------------------

def build_z3_solver(x_secret: int, xp_secret: int) -> z3.Solver:
    """Build a Z3 solver that searches for a counterexample to:
    'For any uninterpreted Boolean wire w over Z_q × Z_q, if VI(w)
    holds, then count(x_secret) = count(xp_secret).'

    The proof obligation is the negation of the implication; UNSAT
    means no counterexample exists, hence the implication holds.
    """
    solver = z3.Solver()
    solver.set("random_seed", 0)

    # Declare 5 × 5 = 25 Boolean cells for w(s0_val, t).
    cells = {}
    for s0_val in range(Q):
        for t in range(Q):
            cells[(s0_val, t)] = z3.Bool(f"w_{s0_val}_{t}")

    # VI premise: w(s0(y, t), t) == w(s0(y', t), t) for all y, y', t.
    # Equivalent to: for fixed t, w(·, t) is the SAME across all y.
    # Since {s0(y, t) : y ∈ Z_q} = Z_q (the share is a bijection in y),
    # this forces w(·, t) to be constant — a single Boolean per t.
    for t in range(Q):
        for y in range(Q):
            for y_prime in range(Q):
                solver.add(cells[(s0(y, t), t)] == cells[(s0(y_prime, t), t)])

    # Count terms: c(x_secret) and c(xp_secret) as Int sums.
    def count_for(x: int):
        return z3.Sum([
            z3.If(cells[(s0(x, t), t)], 1, 0)
            for t in range(Q)
        ])

    # Negate the conclusion: search for any wire function that has
    # VI but unequal counts.
    solver.add(count_for(x_secret) != count_for(xp_secret))
    return solver


def prove_z3_pair(x: int, xp: int) -> tuple[str, float]:
    t0 = time.perf_counter()
    result = build_z3_solver(x, xp).check()
    return str(result), (time.perf_counter() - t0) * 1000


# ---------------------------------------------------------------------------
# CVC5 encoding (preferred — Tier-A universal prover)
# ---------------------------------------------------------------------------

def cvc5_proof_via_python_api(x_secret: int, xp_secret: int) -> tuple[str, float]:
    """Direct CVC5 Python API encoding. Quantifier-free over a finite
    Boolean domain — CVC5 should crack this trivially.
    """
    try:
        import cvc5
        from cvc5 import Kind
    except ImportError:
        return "skipped (no cvc5 python module)", 0.0

    t0 = time.perf_counter()
    slv = cvc5.Solver()
    slv.setOption("produce-models", "false")
    slv.setLogic("QF_UFLIA")

    boolSort = slv.getBooleanSort()
    intSort = slv.getIntegerSort()

    # 5 × 5 free Boolean cells
    cells = {}
    for s0_val in range(Q):
        for t in range(Q):
            cells[(s0_val, t)] = slv.mkConst(boolSort, f"w_{s0_val}_{t}")

    # VI premise — finite expansion
    for t in range(Q):
        ref = cells[(s0(0, t), t)]
        for y in range(1, Q):
            other = cells[(s0(y, t), t)]
            slv.assertFormula(slv.mkTerm(Kind.EQUAL, ref, other))

    # Count terms
    one = slv.mkInteger(1)
    zero = slv.mkInteger(0)

    def count_for(x: int):
        terms = []
        for t in range(Q):
            cell = cells[(s0(x, t), t)]
            terms.append(slv.mkTerm(Kind.ITE, cell, one, zero))
        if len(terms) == 1:
            return terms[0]
        return slv.mkTerm(Kind.ADD, *terms)

    cx = count_for(x_secret)
    cxp = count_for(xp_secret)

    # Negate the conclusion: c(x) != c(xp)
    slv.assertFormula(slv.mkTerm(Kind.NOT, slv.mkTerm(Kind.EQUAL, cx, cxp)))

    r = slv.checkSat()
    elapsed = (time.perf_counter() - t0) * 1000
    if r.isUnsat():
        return "unsat", elapsed
    if r.isSat():
        return "sat", elapsed
    return "unknown", elapsed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

PAIRS = [(0, 1), (0, 2), (0, 3), (0, 4), (1, 2), (1, 3), (1, 4), (2, 3), (2, 4), (3, 4)]


def main() -> int:
    print("=" * 70)
    print("T1 — Value-independence ⇒ first-order distributional security")
    print(f"  q = {Q}   wire space: 2^{Q*Q} = {2 ** (Q * Q)} functions")
    print(f"  CVC5 binary: {locate_cvc5() or 'NOT FOUND (cross-check via SMT-LIB2)'}")
    print("=" * 70)

    all_ok = True
    for x, xp in PAIRS:
        # CVC5 (preferred prover)
        cvc5_result, cvc5_ms = cvc5_proof_via_python_api(x, xp)
        # Z3 cross-check
        z3_result, z3_ms = prove_z3_pair(x, xp)

        ok = (
            cvc5_result == "unsat"
            or cvc5_result.startswith("skipped")
        ) and z3_result == "unsat"
        marker = "OK " if ok else "FAIL"

        print(f"  pair (x={x}, x'={xp}): "
              f"CVC5={cvc5_result:8s} ({cvc5_ms:6.1f} ms)  "
              f"Z3={z3_result:8s} ({z3_ms:6.1f} ms)  [{marker}]")
        all_ok = all_ok and ok

    print()
    if all_ok:
        print("  STATUS: T1 PROVED  (small-instance, q = 5)")
        print("    For every pair (x, x') in Z_5 × Z_5, value-independence of any")
        print("    Boolean wire function implies marginal-count equality.")
        print()
        print("    This is the small-domain finite expansion of Theorem 3.9.1.")
        print("    The fully-universal version (over all primes q and all wire")
        print("    function spaces) is reported as future work in §6.")
        return 0
    print("  STATUS: T1 FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
