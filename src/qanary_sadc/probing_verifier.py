"""
Probing Security Verifier — Structural Dependency Analysis

Implements M0 Formal Specification (v0.3.1) for first-order probing security
verification via structural dependency checking.

Approach (SILVER-style):
    A wire that depends on at most one share group of a 2-share masking scheme
    is guaranteed independent of the secret. This is a sound overapproximation:
    no false negatives, but possible false positives for re-masked wires.

    For unmasked circuits, dependency on the secret is the exact check.

Sections implemented:
    4.1 — Structural dependency queries D₀, D₁ (masked)
    4.2 — Soundness argument (unconstrained domain)
    4.3 — Boolean self-check table (7 rows)
    4.8 — Unmasked verification D_s and self-check table (4 rows)

Milestones: M1 (1-bit Boolean), M2 (8-bit Boolean), M3 (12/23-bit Arithmetic)

False-Positive Analysis (M2):
    Structural dependency is a sound overapproximation: it has NO false negatives
    but can produce false positives for wires that are statistically independent
    despite syntactically depending on both share groups.

    Known FP classes (confirmed by M2 test suite):

    1. Re-masked cross-domain products:
       w = (a0 & b1) ^ z_fresh → structurally depends on s0 AND s1,
       but z_fresh masks the dependency. Coco-Alma would report SECURE.
       Prevalence: Every DOM AND output wire (2 per gate × N bits).

    2. Complete DOM AND outputs:
       q0 = (a0&b0) ^ ((a0&b1) ^ z) → structurally insecure, but
       the fresh randomness z ensures statistical independence.
       This is the fundamental FP of structural analysis.

    3. Pipeline-registered cross-domain terms:
       After a register boundary, glitch propagation is blocked.
       Structural analysis ignores timing — it sees the combinational
       cone only. This produces FPs for properly-pipelined DOM gates.

    NOT a false positive:
    - MUX(p, s0, s1) where p is public: structurally AND statistically
      insecure because the attacker controls p and can select shares.

    Empirical FP rate on OpenTitan DOM AND (DW=8):
       24 wires tested total: 16 output (8 × q0, 8 × q1) + 8 inner-domain
       All 24 wires are actually secure (DOM AND with fresh z is secure).
       16/16 output wires flagged POTENTIALLY_INSECURE (all are structural FPs)
       8/8 inner-domain wires correctly flagged SECURE
       FP rate: 16/24 = 66.7% (denominator = all tested secure wires)
       False negative rate: 0% (verified on separate insecure test wires)

References:
    - M0 Spec: .claude/research/M0_FORMAL_SPECIFICATION.md
    - SILVER: Knichel et al., ASIACRYPT 2020
    - ISW: Ishai-Sahai-Wagner, CRYPTO 2003
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class ProbingVerifierError(Exception):
    """Base error for probing security verification."""


class EncodingError(ProbingVerifierError):
    """Error in SMT encoding of dependency query."""


# =============================================================================
# Enums
# =============================================================================


class SecurityVerdict(Enum):
    """Security verdict from structural dependency analysis."""

    SECURE = "secure"
    POTENTIALLY_INSECURE = "potentially_insecure"
    UNKNOWN = "unknown"


class VerificationMode(Enum):
    """Verification mode based on circuit type."""

    MASKED = "masked"  # D₀/D₁ queries (Section 4.1)
    UNMASKED = "unmasked"  # D_s query (Section 4.8)


# =============================================================================
# Result Dataclasses
# =============================================================================


@dataclass
class DependencyResult:
    """Result of a single dependency query (D₀, D₁, or D_s).

    Attributes:
        query_name: Identifier ("D0", "D1", or "Ds").
        satisfiable: True=SAT (depends), False=UNSAT (independent),
                     None=unknown/timeout.
        counterexample: If SAT, concrete variable assignments.
        time_seconds: Wall-clock time for this query.
    """

    query_name: str
    satisfiable: bool | None
    counterexample: dict[str, Any] | None
    time_seconds: float


@dataclass
class WireSecurityResult:
    """Security verdict for a single wire.

    Attributes:
        wire_name: Human-readable wire identifier.
        verdict: SECURE, POTENTIALLY_INSECURE, or UNKNOWN.
        depends_on_s0: D₀ SAT result (masked mode only).
        depends_on_s1: D₁ SAT result (masked mode only).
        depends_on_secret: D_s SAT result (unmasked mode only).
        dependency_results: Raw DependencyResult for each query.
        time_seconds: Total wall-clock time for all queries.
    """

    wire_name: str
    verdict: SecurityVerdict
    depends_on_s0: bool | None = None
    depends_on_s1: bool | None = None
    depends_on_secret: bool | None = None
    dependency_results: list[DependencyResult] = field(default_factory=list)
    time_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "wire_name": self.wire_name,
            "verdict": self.verdict.value,
            "depends_on_s0": self.depends_on_s0,
            "depends_on_s1": self.depends_on_s1,
            "depends_on_secret": self.depends_on_secret,
            "time_seconds": self.time_seconds,
        }

    def __str__(self) -> str:
        if self.depends_on_secret is not None:
            dep = f"secret={'yes' if self.depends_on_secret else 'no'}"
        else:
            s0 = (
                "yes"
                if self.depends_on_s0
                else ("?" if self.depends_on_s0 is None else "no")
            )
            s1 = (
                "yes"
                if self.depends_on_s1
                else ("?" if self.depends_on_s1 is None else "no")
            )
            dep = f"s0={s0}, s1={s1}"
        return f"WireSecurityResult({self.wire_name}: {self.verdict.value}, {dep})"


# =============================================================================
# Main Verifier
# =============================================================================


class ProbingVerifier:
    """
    Structural dependency verifier for first-order probing security.

    Implements the D₀/D₁ queries (masked, Section 4.1) and D_s query
    (unmasked, Section 4.8) from the M0 formal specification.

    Usage:
        verifier = ProbingVerifier()

        # Masked: check if wire depends on both share groups
        result = verifier.check_masked_wire(
            wire_fn=lambda s0, s1, r, p: s0 & s1,
            s0_width=1, s1_width=1,
            wire_name="and_shares",
        )
        assert result.verdict == SecurityVerdict.POTENTIALLY_INSECURE

        # Self-checks: all 7 Boolean rows must pass
        checks = verifier.run_self_checks(VerificationMode.MASKED)
        assert all(passed for _, passed in checks)
    """

    def __init__(self, timeout_ms: int = 10_000):
        self.timeout_ms = timeout_ms
        self._z3 = None

    def _ensure_z3(self):
        """Lazy-import Z3 solver."""
        if self._z3 is None:
            try:
                import z3

                self._z3 = z3
            except ImportError as e:
                raise ProbingVerifierError(
                    "Z3 not found. Install with: pip install z3-solver"
                ) from e
        return self._z3

    def _run_dependency_query(
        self,
        constraints: list,
        query_name: str,
    ) -> DependencyResult:
        """
        Core SMT query: ∃ vars : constraint₁ ∧ constraint₂ ∧ ...

        Args:
            constraints: Z3 constraints (typically [var_differ, wire_differ]).
            query_name: "D0", "D1", or "Ds".

        Returns:
            DependencyResult with SAT/UNSAT/None and optional counterexample.
        """
        z3 = self._ensure_z3()
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)

        for c in constraints:
            solver.add(c)

        start = time.time()
        result = solver.check()
        elapsed = time.time() - start

        if result == z3.sat:
            model = solver.model()
            cex: dict[str, Any] = {}
            for d in model.decls():
                val = model[d]
                if hasattr(val, "as_long"):
                    cex[str(d.name())] = val.as_long()
                elif z3.is_true(val):
                    cex[str(d.name())] = True
                elif z3.is_false(val):
                    cex[str(d.name())] = False
                else:
                    cex[str(d.name())] = str(val)
            return DependencyResult(query_name, True, cex, elapsed)
        elif result == z3.unsat:
            return DependencyResult(query_name, False, None, elapsed)
        else:
            return DependencyResult(query_name, None, None, elapsed)

    def check_masked_wire(
        self,
        wire_fn: Callable,
        s0_width: int,
        s1_width: int,
        r_width: int = 0,
        p_width: int = 0,
        wire_name: str = "",
    ) -> WireSecurityResult:
        """
        Check structural dependency for a masked wire (spec Section 4.1).

        Runs two queries:
          D₀: ∃ s₀≠s₀', s₁, r, p : w(s₀,s₁,r,p) ≠ w(s₀',s₁,r,p)
          D₁: ∃ s₀, s₁≠s₁', r, p : w(s₀,s₁,r,p) ≠ w(s₀,s₁',r,p)

        Decision table:
          D₀=UNSAT, D₁=UNSAT → SECURE (constant or depends only on r/p)
          D₀=SAT,   D₁=UNSAT → SECURE (depends only on s₀, uniform)
          D₀=UNSAT, D₁=SAT   → SECURE (depends only on s₁, uniform)
          D₀=SAT,   D₁=SAT   → POTENTIALLY_INSECURE

        Args:
            wire_fn: Callable(s0, s1, r, p) -> Z3 expression.
                     r and p are None when respective width is 0.
            s0_width: Bit width of share-0 group.
            s1_width: Bit width of share-1 group.
            r_width: Bit width of fresh randomness (0 = none).
            p_width: Bit width of public inputs (0 = none).
            wire_name: Human-readable name for reporting.

        Returns:
            WireSecurityResult with verdict and dependency details.
        """
        z3 = self._ensure_z3()
        start = time.time()

        r = z3.BitVec("r", r_width) if r_width > 0 else None
        p = z3.BitVec("p", p_width) if p_width > 0 else None

        # D₀: vary s₀, fix s₁/r/p
        s0 = z3.BitVec("s0", s0_width)
        s0p = z3.BitVec("s0p", s0_width)
        s1 = z3.BitVec("s1", s1_width)

        w_d0 = wire_fn(s0, s1, r, p)
        w_d0p = wire_fn(s0p, s1, r, p)

        d0 = self._run_dependency_query(
            [s0 != s0p, w_d0 != w_d0p], "D0"
        )

        # D₁: vary s₁, fix s₀/r/p
        s1p = z3.BitVec("s1p", s1_width)

        w_d1 = wire_fn(s0, s1, r, p)
        w_d1p = wire_fn(s0, s1p, r, p)

        d1 = self._run_dependency_query(
            [s1 != s1p, w_d1 != w_d1p], "D1"
        )

        elapsed = time.time() - start

        # Decision table (M0 spec Section 4.1)
        if d0.satisfiable is None or d1.satisfiable is None:
            verdict = SecurityVerdict.UNKNOWN
        elif d0.satisfiable and d1.satisfiable:
            verdict = SecurityVerdict.POTENTIALLY_INSECURE
        else:
            verdict = SecurityVerdict.SECURE

        return WireSecurityResult(
            wire_name=wire_name,
            verdict=verdict,
            depends_on_s0=d0.satisfiable,
            depends_on_s1=d1.satisfiable,
            dependency_results=[d0, d1],
            time_seconds=elapsed,
        )

    def check_unmasked_wire(
        self,
        wire_fn: Callable,
        s_width: int,
        p_width: int = 0,
        wire_name: str = "",
    ) -> WireSecurityResult:
        """
        Check secret dependency for an unmasked wire (spec Section 4.8).

        Runs one query:
          D_s: ∃ s≠s', p : w(s,p) ≠ w(s',p)

        Decision:
          UNSAT → SECURE (no secret dependency)
          SAT   → POTENTIALLY_INSECURE (depends on secret)

        For unmasked circuits this is the exact check (no false positives).

        Args:
            wire_fn: Callable(s, p) -> Z3 expression.
                     p is None when p_width is 0.
            s_width: Bit width of the secret.
            p_width: Bit width of public inputs (0 = none).
            wire_name: Human-readable name for reporting.

        Returns:
            WireSecurityResult with verdict and dependency details.
        """
        z3 = self._ensure_z3()
        start = time.time()

        s = z3.BitVec("s", s_width)
        sp = z3.BitVec("sp", s_width)
        p = z3.BitVec("p", p_width) if p_width > 0 else None

        w_orig = wire_fn(s, p)
        w_prime = wire_fn(sp, p)

        ds = self._run_dependency_query(
            [s != sp, w_orig != w_prime], "Ds"
        )

        elapsed = time.time() - start

        if ds.satisfiable is None:
            verdict = SecurityVerdict.UNKNOWN
        elif ds.satisfiable:
            verdict = SecurityVerdict.POTENTIALLY_INSECURE
        else:
            verdict = SecurityVerdict.SECURE

        return WireSecurityResult(
            wire_name=wire_name,
            verdict=verdict,
            depends_on_secret=ds.satisfiable,
            dependency_results=[ds],
            time_seconds=elapsed,
        )

    # =========================================================================
    # Self-Check Tables
    # =========================================================================

    def run_self_checks(
        self, mode: VerificationMode
    ) -> list[tuple[str, bool]]:
        """
        Run mandatory self-check table from M0 spec.

        For MASKED: 7-row Boolean table (Section 4.3, uses 1-bit shares).
        For UNMASKED: 4-row table (Section 4.8, uses 8-bit secret/public).

        Self-checks validate the SMT encoding correctness. The M2 test suite
        separately verifies 8-bit share widths with Extract-based wire functions.

        Returns:
            List of (check_name, passed) tuples. ALL must pass.
            If any fail, the encoding is wrong — do not proceed.
        """
        if mode == VerificationMode.MASKED:
            return self._run_boolean_self_checks()
        return self._run_unmasked_self_checks()

    def run_arithmetic_self_checks(
        self, n: int, q: int
    ) -> list[tuple[str, bool]]:
        """
        Run mandatory arithmetic self-check table from M0 spec Section 4.4.

        Uses the same D₀/D₁ structural dependency queries as Boolean masking
        but with n-bit share widths and arithmetic wire functions (carry, sum).
        The modulus q is used only for labeling — the structural queries treat
        shares as unconstrained n-bit vectors (sound overapproximation).
        Unconstrained {0,1}^n ⊇ ℤ_q, so any dependency found over ℤ_q is
        also found here, but not vice versa (M0 §4.2 domain note).

        Args:
            n: Bit width of shares (12 for ML-KEM, 23 for ML-DSA).
            q: Arithmetic modulus (3329 for ML-KEM, 8380417 for ML-DSA).

        Returns:
            List of (check_name, passed) tuples. ALL must pass.
        """
        z3 = self._ensure_z3()
        results: list[tuple[str, bool]] = []

        msb = n - 1

        # (name, wire_fn, expected_d0, expected_d1, expected_verdict)
        checks = [
            (
                f"w=s0[0] (n={n})",
                lambda s0, s1, r, p: z3.Extract(0, 0, s0),
                True, False, SecurityVerdict.SECURE,
            ),
            (
                f"w=s1[0] (n={n})",
                lambda s0, s1, r, p: z3.Extract(0, 0, s1),
                False, True, SecurityVerdict.SECURE,
            ),
            (
                f"w=carry(s0+s1) (n={n})",
                lambda s0, s1, r, p, _n=n: z3.Extract(
                    _n, _n, z3.ZeroExt(1, s0) + z3.ZeroExt(1, s1)
                ),
                True, True, SecurityVerdict.POTENTIALLY_INSECURE,
            ),
            (
                f"w=(s0+s1)[0] (n={n})",
                lambda s0, s1, r, p: z3.Extract(0, 0, s0 + s1),
                True, True, SecurityVerdict.POTENTIALLY_INSECURE,
            ),
            (
                f"w=s0[0]^s1[0] (n={n})",
                lambda s0, s1, r, p: z3.Extract(0, 0, s0) ^ z3.Extract(0, 0, s1),
                True, True, SecurityVerdict.POTENTIALLY_INSECURE,
            ),
            (
                f"w=s0[{msb}] (n={n})",
                lambda s0, s1, r, p, _msb=msb: z3.Extract(_msb, _msb, s0),
                True, False, SecurityVerdict.SECURE,
            ),
        ]

        for name, wire_fn, exp_d0, exp_d1, exp_verdict in checks:
            result = self.check_masked_wire(
                wire_fn=wire_fn,
                s0_width=n,
                s1_width=n,
                wire_name=name,
            )
            passed = (
                result.verdict == exp_verdict
                and result.depends_on_s0 == exp_d0
                and result.depends_on_s1 == exp_d1
            )
            d0_str = "SAT" if exp_d0 else "UNSAT"
            d1_str = "SAT" if exp_d1 else "UNSAT"
            results.append((
                f"{name}: {exp_verdict.value} (D0={d0_str}, D1={d1_str})",
                passed,
            ))

        return results

    def _run_boolean_self_checks(self) -> list[tuple[str, bool]]:
        """M0 spec Section 4.3: 7-row mandatory Boolean self-check table."""
        z3 = self._ensure_z3()
        results: list[tuple[str, bool]] = []

        # (name, wire_fn, r_width, expected_d0, expected_d1, expected_verdict)
        checks = [
            (
                "w=s0",
                lambda s0, s1, r, p: s0,
                0, True, False, SecurityVerdict.SECURE,
            ),
            (
                "w=s1",
                lambda s0, s1, r, p: s1,
                0, False, True, SecurityVerdict.SECURE,
            ),
            (
                "w=s0&s1",
                lambda s0, s1, r, p: s0 & s1,
                0, True, True, SecurityVerdict.POTENTIALLY_INSECURE,
            ),
            (
                "w=s0^s1",
                lambda s0, s1, r, p: s0 ^ s1,
                0, True, True, SecurityVerdict.POTENTIALLY_INSECURE,
            ),
            (
                "w=s0^r",
                lambda s0, s1, r, p: s0 ^ r,
                1, True, False, SecurityVerdict.SECURE,
            ),
            (
                "w=r",
                lambda s0, s1, r, p: r,
                1, False, False, SecurityVerdict.SECURE,
            ),
            (
                "w=1",
                lambda s0, s1, r, p: z3.BitVecVal(1, 1),
                0, False, False, SecurityVerdict.SECURE,
            ),
        ]

        for name, wire_fn, r_width, exp_d0, exp_d1, exp_verdict in checks:
            result = self.check_masked_wire(
                wire_fn=wire_fn,
                s0_width=1,
                s1_width=1,
                r_width=r_width,
                wire_name=name,
            )
            passed = (
                result.verdict == exp_verdict
                and result.depends_on_s0 == exp_d0
                and result.depends_on_s1 == exp_d1
            )
            d0_str = "SAT" if exp_d0 else "UNSAT"
            d1_str = "SAT" if exp_d1 else "UNSAT"
            results.append((
                f"{name}: {exp_verdict.value} (D0={d0_str}, D1={d1_str})",
                passed,
            ))

        return results

    def _run_unmasked_self_checks(self) -> list[tuple[str, bool]]:
        """M0 spec Section 4.8: 4-row mandatory unmasked self-check table."""
        z3 = self._ensure_z3()
        results: list[tuple[str, bool]] = []

        # (name, wire_fn, expected_dep, expected_verdict)
        checks = [
            (
                "w=s[0]",
                lambda s, p: z3.Extract(0, 0, s),
                True, SecurityVerdict.POTENTIALLY_INSECURE,
            ),
            (
                "w=p[0]",
                lambda s, p: z3.Extract(0, 0, p),
                False, SecurityVerdict.SECURE,
            ),
            (
                "w=(s<p)",
                lambda s, p: z3.If(
                    z3.ULT(s, p),
                    z3.BitVecVal(1, 1),
                    z3.BitVecVal(0, 1),
                ),
                True, SecurityVerdict.POTENTIALLY_INSECURE,
            ),
            (
                "w=1",
                lambda s, p: z3.BitVecVal(1, 1),
                False, SecurityVerdict.SECURE,
            ),
        ]

        for name, wire_fn, exp_dep, exp_verdict in checks:
            result = self.check_unmasked_wire(
                wire_fn=wire_fn,
                s_width=8,
                p_width=8,
                wire_name=name,
            )
            passed = (
                result.verdict == exp_verdict
                and result.depends_on_secret == exp_dep
            )
            ds_str = "SAT" if exp_dep else "UNSAT"
            results.append((
                f"{name}: {exp_verdict.value} (Ds={ds_str})",
                passed,
            ))

        return results
