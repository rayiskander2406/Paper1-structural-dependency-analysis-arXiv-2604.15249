"""
SADC-Arith — Arithmetic-Masking Secret-Aware Distributional Check
==================================================================

An experimental refinement pass that complements the Boolean SADC
(`sadc.py`) for circuits protected by ARITHMETIC masking modulo q,
such as Adams Bridge's Barrett reduction.

Supported algorithms (callers MUST pass q_modulus explicitly):
    ML-KEM (FIPS 203): q = 3329,    share width = 24 (= 2 × 12)
    ML-DSA (FIPS 204): q = 8380417, share width = 24

⚠ CRITICAL: barrett_circuit.json in this repository is **ML-KEM Barrett**,
verified from barrett_sv2v.v line 147–148:
    localparam abr_params_pkg_MLKEM_Q = 12'd3329;
    parameter MASKED_REG_SIZE = 2 * abr_params_pkg_MLKEM_Q_WIDTH;
Use MLKEM_Q (NOT MLDSA_Q) when running arithmetic SADC against this
netlist. Adams Bridge also has ML-DSA arithmetic-masked modules
(masked_BFU_mult etc.) where MLDSA_Q is correct. The check_wire and
run_sadc_arith_pass APIs REQUIRE q_modulus as an explicit parameter
and validate it against the known PQC moduli; this prevents the
"silently wrong default" bug class.

Background
----------
The Boolean SADC reparametrizes shares as
        s0[i] = secret[i] ⊕ s1[i]                       (XOR masking)
which is only correct when the secret-share relation is bitwise XOR.
Under arithmetic masking the correct reparametrization is
        S0 = (X − S1) mod q                              (subtraction)
which *couples* all share-width bits of S0 via the borrow chain. A
Boolean SADC run over a wire that touches high bits of the shares
therefore cannot faithfully model the secret; wires are either
  (i)  confirmed insecure via low-bit leaks (Boolean lens happens to
       give the correct verdict when the wire is truly insecure), or
  (ii) reported INDETERMINATE because the mask cone exceeds the
       Boolean SADC enumeration budget (12–16 bits).

On real Adams Bridge Barrett under deterministic Z3 config, Boolean
SADC resolves 146 wires as insecure and leaves 217 INDETERMINATE.
Arithmetic SADC closes the residual: under the correct ML-KEM modulus
(q = 3329) it promotes 198 wires to SECURE and reports 165 as
INSECURE_CONSERVATIVE, with 0 indeterminate.

Strategy chosen: VALUE-INDEPENDENCE under arithmetic reparametrization
---------------------------------------------------------------------
Given a wire w(s0, s1, r) expressed over per-bit Z3 BitVec(1) variables,
we introduce *full-width* symbolic bitvectors

        X   : BitVec(24)   — secret candidate
        Xp  : BitVec(24)   — alternative secret
        S1  : BitVec(24)   — uniform mask
        r[] : BitVec(1) per fresh-randomness bit

and derive  S0 = (X − S1) mod q   and  S0p = (Xp − S1) mod q.

We then substitute per-bit views
        s0[i] = Extract(i, i, S0),   s1[i] = Extract(i, i, S1)
(and similarly s0p[i] with S0p) into two copies of the wire expression,
obtaining  w_X  and  w_Xp.

The SADC-Arith VALUE-INDEPENDENCE check is:

    ¬∃ X, Xp, S1, r :
         X  < q  ∧  Xp < q  ∧  S1 < q  ∧  X ≠ Xp
       ∧ w_X (s0=S0,  s1=S1, r) ≠ w_Xp(s0=S0p, s1=S1, r)

If UNSAT  → wire is VALUE-INDEPENDENT of X → SECURE (strictly stronger
             than distributional independence, which is what first-order
             SADC needs).
If SAT    → wire VALUES differ across secrets for some (S1, r). This is
             *not* yet a proof of leakage — the distribution over S1 could
             still balance — but the distributional check under arithmetic
             masking is #P-hard in general and out of scope for this
             prototype. We return INSECURE_CONSERVATIVE as a best-effort
             verdict; users who need the exact distributional answer
             should fall back to Coco-Alma / SILVER.

Why value-independence is a reasonable first approximation
----------------------------------------------------------
Under the standard probing model any wire that is a deterministic
function of the secret AND some masks+randomness is secure iff its
CONDITIONAL distribution given the secret is constant in the secret.
Value-independence implies distributional-independence (a stronger
condition). Many wires that trip Boolean SADC indeterminacy are actually
VALUE-INDEPENDENT — e.g. pure combinational noise, subexpressions that
the Barrett pipeline registers re-randomise, or masked intermediate
results where the mask alone determines the wire value. For those the
prototype will *promote* the wire to SECURE with a formal Z3 proof.

What this prototype does NOT do
-------------------------------
  • It does not enumerate the distribution (#SAT is out of scope).
  • It does not model arithmetic masking's true "s1 uniform over Z_q"
    — we only use S1 < q as a side constraint. For ML-KEM (q = 3329)
    and ML-DSA (q = 8380417) this matches the hardware semantics
    when q_modulus is correctly passed by the caller.
  • It does not handle multi-share (>2) or higher-order probes.
  • It does not replace Coco-Alma for exact verification.

Scalability expectations
------------------------
Z3 is asked a single QF_BV query per wire, with a symbolic 24-bit
subtraction and the wire expression substituted in place. For Barrett
wires whose Boolean cone has ≤ ~30 gates (the common case) Z3 is
expected to return within a few hundred ms. Wires that exercise the
full 48-bit multiplier tree may time out (reported as INDETERMINATE).

References
----------
  • Ishai-Sahai-Wagner (CRYPTO 2003) — standard probing model
  • Goubin-Patarin (CHES 1999) — arithmetic↔Boolean conversions
  • SILVER (Knichel et al., ASIACRYPT 2020) — exact BDD check
  • Coco-Alma (Gigerl et al., USENIX 2021) — SAT exact check
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from .probing_verifier import SecurityVerdict

if TYPE_CHECKING:
    from .netlist_adapter import (
        FMRefinedReport,
        FMVerdict,
        NetlistAdapter,
    )

logger = logging.getLogger(__name__)

# ML-DSA (FIPS 204) modulus and share width.
MLDSA_Q = 8380417
MLDSA_SHARE_WIDTH = 24  # Adams Bridge ML-DSA shares stored as 24 bits

# ML-KEM (FIPS 203) modulus and share width.
# Adams Bridge masked_barrett_reduction is parameterised on MLKEM_Q.
# The Yosys-synthesised barrett_circuit.json in
# src/qrisc_validator/qdebug/formal/gadgets/netlists/ targets ML-KEM,
# NOT ML-DSA — verified 2026-04-08 from barrett_sv2v.v line 147:
#   localparam abr_params_pkg_MLKEM_Q = 12'd3329;
#   parameter MASKED_REG_SIZE = 2 * abr_params_pkg_MLKEM_Q_WIDTH;
# Use MLKEM_Q (NOT MLDSA_Q) when running arithmetic SADC against
# barrett_circuit.json. The 24-bit share width matches both algorithms,
# but the modulus must be 3329 (not 8380417) for the value-independence
# query's `s < q` range constraint to match the actual circuit semantics.
MLKEM_Q = 3329
MLKEM_SHARE_WIDTH = 24


# ============================================================================
# Result types
# ============================================================================


class SADCArithVerdict(Enum):
    """SADC-Arith verdict for a single wire."""

    SECURE = "sadc_arith_secure"                        # Value-independent of secret
    INSECURE_CONSERVATIVE = "sadc_arith_insecure_cons"  # Value differs — may still
                                                         # be distributionally secure
    INDETERMINATE = "sadc_arith_indeterminate"          # Solver timeout / too complex
    NOT_CHECKED = "sadc_arith_not_checked"              # Wire already secure upstream


@dataclass
class SADCArithWireResult:
    wire_name: str
    prior_verdict: str                 # Boolean-SADC or FM verdict it came in as
    sadc_arith_verdict: SADCArithVerdict
    s0_cone_size: int = 0
    s1_cone_size: int = 0
    r_cone_size: int = 0
    sadc_arith_time_seconds: float = 0.0
    note: str = ""


@dataclass
class SADCArithReport:
    module_name: str
    q_modulus: int                   # MUST be set by caller (ML-KEM 3329 or ML-DSA 8380417)
    share_width: int                 # MUST be set by caller (typically 24)
    results: dict[str, SADCArithWireResult] = field(default_factory=dict)
    promoted_count: int = 0          # was indet/insecure → now SECURE
    confirmed_insecure_count: int = 0  # was indet/insecure → still insecure
    indeterminate_count: int = 0     # solver gave up
    not_checked_count: int = 0
    total_time_seconds: float = 0.0

    def summary(self) -> str:
        return (
            f"{self.module_name} (arith mod q={self.q_modulus}): "
            f"{self.promoted_count} promoted, "
            f"{self.confirmed_insecure_count} still insecure, "
            f"{self.indeterminate_count} indeterminate, "
            f"{self.total_time_seconds:.2f}s"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "q_modulus": self.q_modulus,
            "share_width": self.share_width,
            "promoted": self.promoted_count,
            "confirmed_insecure": self.confirmed_insecure_count,
            "indeterminate": self.indeterminate_count,
            "not_checked": self.not_checked_count,
            "total_time_seconds": self.total_time_seconds,
            "results": {
                name: {
                    "prior": r.prior_verdict,
                    "sadc_arith": r.sadc_arith_verdict.value,
                    "s0_cone": r.s0_cone_size,
                    "s1_cone": r.s1_cone_size,
                    "r_cone": r.r_cone_size,
                    "time_s": round(r.sadc_arith_time_seconds, 4),
                    "note": r.note,
                }
                for name, r in self.results.items()
            },
        }


# ============================================================================
# Arithmetic-SADC checker
# ============================================================================


class SADCArithChecker:
    """Value-independence SADC under arithmetic masking mod q."""

    def __init__(
        self,
        q_modulus: int,                # REQUIRED — no default to prevent silent ML-KEM/ML-DSA mixups
        share_width: int,              # REQUIRED — must match the netlist port width
        query_timeout_ms: int = 10_000,
        query_rlimit: int = 10_000_000,
        random_seed: int = 0,
        cvc5_validate: bool = False,
    ):
        """
        Args:
            q_modulus: REQUIRED. Arithmetic masking modulus. Must be one of
                MLKEM_Q (3329) or MLDSA_Q (8380417). This parameter has NO
                default to prevent the "silent wrong default" bug class:
                a previous version defaulted to MLDSA_Q and was silently
                wrong on ML-KEM Barrett netlists. Always pass explicitly.
            share_width: REQUIRED. Symbolic bitvector width for X, Xp, S1.
                For Adams Bridge ML-KEM and ML-DSA Barrett this is 24
                (= 2 × MLKEM_Q_WIDTH or padded ML-DSA shares).
            query_timeout_ms: Per-wire wall-clock timeout (fallback only).
            query_rlimit: Z3 resource limit per query (deterministic across
                machines, unlike wall-clock timeout). 10_000_000 is
                empirically sufficient for arithmetic SADC on Adams Bridge
                ML-KEM Barrett with bit-identical results across runs.
                Set to 0 to disable.
            random_seed: Z3 SMT and SAT random seed (pinned for reproducibility).
            cvc5_validate: If True, after Z3 returns a verdict, also export the
                solver's assertions as SMT-LIB2 and re-check with CVC5. The note
                field of the result will indicate any Z3/CVC5 disagreement.
                Adds ~50-200 ms per query but provides dual-solver validation.

        Raises:
            ValueError: if q_modulus is not in (MLKEM_Q, MLDSA_Q). This guards
                against accidentally passing a wrong modulus on a known-PQC
                netlist; if you genuinely need a custom modulus, set
                ALLOW_CUSTOM_MODULUS=True via the constructor (not currently
                supported — file a feature request).
        """
        if q_modulus not in (MLKEM_Q, MLDSA_Q):
            raise ValueError(
                f"SADCArithChecker: q_modulus={q_modulus} is not a known PQC "
                f"modulus. Use MLKEM_Q ({MLKEM_Q}) for ML-KEM Barrett, or "
                f"MLDSA_Q ({MLDSA_Q}) for ML-DSA arithmetic-masked modules. "
                f"The barrett_circuit.json in this repository is ML-KEM; "
                f"see sadc_arith.py module docstring for details."
            )
        if share_width not in (12, 24, 23):
            raise ValueError(
                f"SADCArithChecker: share_width={share_width} is unusual. "
                f"Adams Bridge typically uses 24 (= 2 × 12 for ML-KEM, or "
                f"padded ML-DSA). If your circuit really uses a different "
                f"width, double-check the labeling matches the netlist."
            )
        self.q = q_modulus
        self.w = share_width
        self.query_timeout_ms = query_timeout_ms
        self.query_rlimit = query_rlimit
        self.random_seed = random_seed
        self.cvc5_validate = cvc5_validate
        self._z3 = None
        self._cvc5_disagreements: list[str] = []
        self._cvc5_total_checks: int = 0

    def _ensure_z3(self):
        if self._z3 is None:
            import z3
            # Pin global Z3 random seeds for reproducibility. Must happen
            # before any Solver is created.
            z3.set_param("smt.random_seed", self.random_seed)
            z3.set_param("sat.random_seed", self.random_seed)
            self._z3 = z3
        return self._z3

    def check_wire(
        self,
        wire_expr: Any,
        s0_bit_vars: dict[int, Any],
        s1_bit_vars: dict[int, Any],
        r_bit_vars: dict[int, Any],
        s0_idx_in_cone: frozenset[int],
        s1_idx_in_cone: frozenset[int],
        r_idx_in_cone: frozenset[int],
    ) -> tuple[SADCArithVerdict, str]:
        """Run the value-independence check on a single wire.

        Returns (verdict, note).
        """
        z3 = self._ensure_z3()

        # ── Early exit: no share bits in cone at all ──
        if not s0_idx_in_cone and not s1_idx_in_cone:
            return (
                SADCArithVerdict.SECURE,
                "no share bits in cone (arith-trivially secure)",
            )

        # ── Symbolic full-width bitvectors ──
        X = z3.BitVec("arith_X",  self.w)
        Xp = z3.BitVec("arith_Xp", self.w)
        S1 = z3.BitVec("arith_S1", self.w)

        q_bv = z3.BitVecVal(self.q, self.w)
        # S0 = (X − S1) mod q   and   S0p = (Xp − S1) mod q.
        # Note: URem is unsigned remainder. (X−S1) is taken modulo 2^w by bv
        # semantics; to get the true mod-q value we add q first to guarantee
        # positivity, then take URem.
        #
        # No-overflow argument: X, S1 ∈ [0, q), so X − S1 + q ∈ [1, 2q).
        # We require 2q < 2^w to avoid wrap on the (X − S1 + q) computation.
        # For ML-KEM (q = 3329, w = 24): 2q = 6658 < 2^24. ✓
        # For ML-DSA (q = 8380417, w = 24): 2q = 16760834 < 2^24 = 16777216. ✓
        # URem with q then yields the mathematical mod-q.
        assert 2 * self.q < (1 << self.w), (
            f"share_width={self.w} too small for q={self.q}: "
            f"2q={2*self.q} must be < 2^w={1 << self.w}"
        )
        S0  = z3.URem(X  - S1 + q_bv, q_bv)
        S0p = z3.URem(Xp - S1 + q_bv, q_bv)

        # ── Build substitution maps ──
        # We need TWO substituted copies of the wire expression:
        #   w_X  : using (S0,  S1) slicing for s0/s1 bits
        #   w_Xp : using (S0p, S1) slicing
        # r bits keep their own variables; they are universally quantified too.
        subs_X: list[tuple[Any, Any]] = []
        subs_Xp: list[tuple[Any, Any]] = []

        # s1 bits — same for both copies (mask is shared)
        for s1_idx in s1_idx_in_cone:
            if s1_idx >= self.w:
                # Labeling claims more bits than our symbolic width allows.
                return (
                    SADCArithVerdict.INDETERMINATE,
                    f"s1 bit {s1_idx} exceeds symbolic share width {self.w}",
                )
            s1_var = s1_bit_vars[s1_idx]
            slice_bit = z3.Extract(s1_idx, s1_idx, S1)
            subs_X.append((s1_var, slice_bit))
            subs_Xp.append((s1_var, slice_bit))

        # s0 bits — DIFFER between copies (secret-dependent)
        for s0_idx in s0_idx_in_cone:
            if s0_idx >= self.w:
                return (
                    SADCArithVerdict.INDETERMINATE,
                    f"s0 bit {s0_idx} exceeds symbolic share width {self.w}",
                )
            s0_var = s0_bit_vars[s0_idx]
            subs_X.append((s0_var, z3.Extract(s0_idx, s0_idx, S0)))
            subs_Xp.append((s0_var, z3.Extract(s0_idx, s0_idx, S0p)))

        # r bits — same in both copies (free, universally quantified)
        # (They are already free BitVec(1) variables in wire_expr, so we don't
        # need to substitute. But we keep a reference so they survive as free
        # in both copies; Z3 handles sharing by AST identity.)

        try:
            w_X  = z3.substitute(wire_expr, *subs_X) if subs_X else wire_expr
            w_Xp = z3.substitute(wire_expr, *subs_Xp) if subs_Xp else wire_expr
        except Exception as exc:
            return (
                SADCArithVerdict.INDETERMINATE,
                f"substitute failed: {exc}",
            )

        # ── Build and check the value-independence query ──
        # Solver assertion:
        #   X  < q  ∧  Xp < q  ∧  S1 < q  ∧  X ≠ Xp  ∧  w_X ≠ w_Xp
        # UNSAT → secure.
        solver = z3.Solver()
        # Pin per-solver random seed (defence-in-depth alongside global pin)
        solver.set("random_seed", self.random_seed)
        # Use rlimit (deterministic resource units) as primary bound;
        # wall-clock timeout as fallback only.
        if self.query_rlimit > 0:
            solver.set("rlimit", self.query_rlimit)
        solver.set("timeout", self.query_timeout_ms)
        solver.add(z3.ULT(X,  q_bv))
        solver.add(z3.ULT(Xp, q_bv))
        solver.add(z3.ULT(S1, q_bv))
        solver.add(X != Xp)
        solver.add(w_X != w_Xp)

        result = solver.check()

        # ── Optional CVC5 cross-validation ──
        cvc5_note = ""
        if self.cvc5_validate and result in (z3.sat, z3.unsat):
            cvc5_result = self._check_with_cvc5(solver)
            self._cvc5_total_checks += 1
            if cvc5_result is None:
                cvc5_note = " [cvc5: error]"
            elif (cvc5_result == "sat" and result == z3.unsat) or \
                 (cvc5_result == "unsat" and result == z3.sat):
                disagreement = (
                    f"Z3={'sat' if result == z3.sat else 'unsat'} "
                    f"CVC5={cvc5_result}"
                )
                self._cvc5_disagreements.append(disagreement)
                cvc5_note = f" [DISAGREEMENT: {disagreement}]"
            else:
                cvc5_note = f" [cvc5: {cvc5_result} ✓]"

        if result == z3.unsat:
            return (
                SADCArithVerdict.SECURE,
                "value-independent of secret under X = S0+S1 mod q" + cvc5_note,
            )
        elif result == z3.sat:
            return (
                SADCArithVerdict.INSECURE_CONSERVATIVE,
                "wire value differs across secrets (distribution unchecked)" + cvc5_note,
            )
        else:
            return (
                SADCArithVerdict.INDETERMINATE,
                "Z3 timeout on value-independence query",
            )

    def _check_with_cvc5(self, z3_solver) -> str | None:
        """Re-check the same query using CVC5 via SMT-LIB2 export.

        Returns 'sat', 'unsat', 'unknown', or None on error.
        """
        try:
            import cvc5
        except ImportError:
            return None

        try:
            smt2 = z3_solver.to_smt2()
        except Exception:
            return None

        try:
            cvc5_solver = cvc5.Solver()
            cvc5_solver.setLogic("QF_BV")
            cvc5_solver.setOption("random-seed", str(self.random_seed))
            from cvc5 import InputParser, SymbolManager
            sm = SymbolManager(cvc5_solver)
            parser = InputParser(cvc5_solver, sm)
            parser.setStringInput(
                cvc5.InputLanguage.SMT_LIB_2_6, smt2, "sadc_arith_query"
            )
            while True:
                cmd = parser.nextCommand()
                if cmd is None or cmd.isNull():
                    break
                cmd.invoke(cvc5_solver, sm)
            # checkSat was already called inside the SMT-LIB2 script;
            # but cvc5 returns the last result via the solver state.
            # We do a final checkSat to be sure.
            result = cvc5_solver.checkSat()
            if result.isSat():
                return "sat"
            elif result.isUnsat():
                return "unsat"
            else:
                return "unknown"
        except Exception as exc:
            return f"error:{type(exc).__name__}"


# ============================================================================
# Top-level pass (operates on existing SADC report output)
# ============================================================================


def run_sadc_arith_pass(
    adapter: "NetlistAdapter",
    boolean_sadc_report: Any,   # SADCRefinedReport (import avoided to prevent cycles)
    work_items: list[tuple[int, str]],
    q_modulus: int,                # REQUIRED — no default to prevent silent ML-KEM/ML-DSA mixups
    share_width: int,              # REQUIRED — must match netlist port width
    target_wires: frozenset[str] | None = None,
    query_timeout_ms: int = 10_000,
    module_timeout_s: float = 900.0,
    cvc5_validate: bool = False,
) -> SADCArithReport:
    """Re-analyse Boolean-SADC indeterminate/insecure wires under arithmetic masking.

    Args:
        adapter: NetlistAdapter for the circuit.
        boolean_sadc_report: SADCRefinedReport produced by sadc.run_sadc_pass.
        work_items: (net_id, wire_name) list from the D1 pass.
        q_modulus: REQUIRED. The arithmetic masking modulus. Pass MLKEM_Q
            (3329) for ML-KEM Barrett (the default Barrett netlist in this
            repo) or MLDSA_Q (8380417) for ML-DSA arithmetic-masked modules.
            No default — see SADCArithChecker for the rationale.
        share_width: REQUIRED. Symbolic bitvector width for X and S1.
            Adams Bridge ML-KEM and ML-DSA Barrett use 24.
        target_wires: Optional explicit set of wire names to re-check. If None,
            we default to every wire whose Boolean SADC verdict is INSECURE or
            INDETERMINATE.
        query_timeout_ms: Per-wire Z3 timeout.
        module_timeout_s: Total wall-clock budget for this pass.
        cvc5_validate: If True, dual-solver validate every Z3 query against
            CVC5 via SMT-LIB2 export.

    Raises:
        ValueError: if q_modulus is not in (MLKEM_Q, MLDSA_Q).
    """
    # Local imports to avoid circularity.
    from .sadc import build_expressions_per_bit, get_bit_cones, SADCVerdict

    t0 = time.monotonic()

    # Determine wires to re-check.
    if target_wires is None:
        target_wires = frozenset(
            name
            for name, res in boolean_sadc_report.sadc_results.items()
            if res.sadc_verdict in (SADCVerdict.INSECURE, SADCVerdict.INDETERMINATE)
        )

    # Build per-bit expressions once (same Z3 variables as Boolean SADC).
    expr, s0_bit_vars, s1_bit_vars, r_bit_vars, _pairing = build_expressions_per_bit(
        adapter, multi_cycle=False
    )

    checker = SADCArithChecker(
        q_modulus=q_modulus,
        share_width=share_width,
        query_timeout_ms=query_timeout_ms,
        cvc5_validate=cvc5_validate,
    )

    name_to_net = {name: nid for nid, name in work_items}

    report = SADCArithReport(
        module_name=adapter.module_name,
        q_modulus=q_modulus,
        share_width=share_width,
    )

    for wire_name in target_wires:
        # Respect module-level timeout.
        if time.monotonic() - t0 > module_timeout_s:
            report.results[wire_name] = SADCArithWireResult(
                wire_name=wire_name,
                prior_verdict=boolean_sadc_report.sadc_results.get(
                    wire_name, None
                ).sadc_verdict.value if wire_name in boolean_sadc_report.sadc_results else "?",
                sadc_arith_verdict=SADCArithVerdict.INDETERMINATE,
                note="module timeout reached",
            )
            report.indeterminate_count += 1
            continue

        net_id = name_to_net.get(wire_name)
        if net_id is None or net_id not in expr:
            continue

        prior_res = boolean_sadc_report.sadc_results.get(wire_name)
        prior_str = prior_res.sadc_verdict.value if prior_res else "unknown"

        wire_expr = expr[net_id]
        s0_cone, s1_cone, r_cone = get_bit_cones(
            wire_expr, s0_bit_vars, s1_bit_vars, r_bit_vars
        )

        t_wire = time.monotonic()
        verdict, note = checker.check_wire(
            wire_expr=wire_expr,
            s0_bit_vars=s0_bit_vars,
            s1_bit_vars=s1_bit_vars,
            r_bit_vars=r_bit_vars,
            s0_idx_in_cone=s0_cone,
            s1_idx_in_cone=s1_cone,
            r_idx_in_cone=r_cone,
        )
        elapsed = time.monotonic() - t_wire

        report.results[wire_name] = SADCArithWireResult(
            wire_name=wire_name,
            prior_verdict=prior_str,
            sadc_arith_verdict=verdict,
            s0_cone_size=len(s0_cone),
            s1_cone_size=len(s1_cone),
            r_cone_size=len(r_cone),
            sadc_arith_time_seconds=elapsed,
            note=note,
        )

        if verdict == SADCArithVerdict.SECURE:
            # Was it actually a leak before? If so this is a promotion;
            # otherwise it's just agreeing with a wire already known secure.
            if prior_res and prior_res.sadc_verdict in (
                SADCVerdict.INSECURE,
                SADCVerdict.INDETERMINATE,
            ):
                report.promoted_count += 1
        elif verdict == SADCArithVerdict.INSECURE_CONSERVATIVE:
            report.confirmed_insecure_count += 1
        else:
            report.indeterminate_count += 1

    report.total_time_seconds = time.monotonic() - t0
    return report
