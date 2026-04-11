"""
SADC — Secret-Aware Distributional Check

The third refinement stage in the QANARY verification hierarchy:
    D0/D1 ⊂ FM ⊂ SADC ⊆ Exact (SILVER/Coco-Alma)

SADC resolves the residual false positives that FM cannot handle by
reparametrizing the wire function from (shares, randomness) to
(secrets, masks + randomness).

Formal definition:
    Let w: {0,1}^n × {0,1}^n × {0,1}^m → {0,1} be a Boolean function of
    shares (s0, s1) and fresh randomness r, under uniform Boolean (XOR)
    masking where the secret is x = s0 ⊕ s1.

    Wire w is SADC-secure iff:
        ∀ x, x' ∈ {0,1}^n :
            Σ_{s1,r} w(x ⊕ s1, s1, r) = Σ_{s1,r} w(x' ⊕ s1, s1, r)

Assumptions:
    A1: First-order probing model (single wire observed)
    A2: Boolean (XOR) masking: s0 = x ⊕ s1, s1 uniform
    A3: Mask and fresh randomness bits independent and uniform
    A4: Wire output is 1-bit

SADC is necessary and sufficient for first-order probing security under A1–A4.

Scalability:
    The distributional check enumerates over all mask + randomness bits in
    the wire's combinational cone. Per-wire cone size is typically small
    for well-structured gadgets (2-8 bits). For larger cones, SADC defers
    (INDETERMINATE) and recommends exact tools.

Hierarchy properties (dual-solver confirmed on DOM AND, ISW refreshed-input):
    - Every FM-secure wire is SADC-secure (strict inclusion)
    - SADC correctly rejects genuine leaks (negative controls: a0⊕a1, Barrett carry)
    - On DOM AND: 75% → 25% (FM) → 0% (SADC)

References:
    - Ishai-Sahai-Wagner, CRYPTO 2003 (standard probing model)
    - SILVER: Knichel et al., ASIACRYPT 2020 (exact via BDD)
    - Coco-Alma: Gigerl et al., USENIX 2021 (exact via SAT)
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
        CircuitReport,
        FMRefinedReport,
        FMVerdict,
        NetlistAdapter,
    )

logger = logging.getLogger(__name__)


# ============================================================================
# Result types
# ============================================================================


class SADCVerdict(Enum):
    """SADC refinement verdict.

    Like FM, SADC is a refinement layer — it can only promote
    (FM-INSECURE → SECURE), never demote. Residual INSECURE
    wires after SADC require exact verification (SILVER/Coco-Alma)
    or represent genuine vulnerabilities.
    """

    SECURE = "sadc_secure"              # Distributional independence proven
    INSECURE = "sadc_insecure"          # Distribution depends on secret
    INDETERMINATE = "sadc_indeterminate" # Cone too large or solver timeout
    NOT_CHECKED = "sadc_not_checked"    # Wire was already SECURE (D1 or FM)


@dataclass
class SADCWireResult:
    """SADC result for a single wire."""

    wire_name: str
    d1_verdict: SecurityVerdict
    fm_verdict: Any  # FMVerdict (avoid circular import)
    sadc_verdict: SADCVerdict
    mask_cone_size: int = 0   # Number of s1 (mask) bits enumerated
    r_cone_size: int = 0      # Number of fresh randomness bits enumerated
    enumeration_count: int = 0  # 2^(mask_cone + r_cone)
    sadc_time_seconds: float = 0.0
    note: str = ""


@dataclass
class SADCRefinedReport:
    """Three-column report: D1 verdicts + FM + SADC refinement.

    Each column is immutable: D1 → FM → SADC. Verdicts are never
    overwritten, only added. See §3.9 of paper v3.0.
    """

    module_name: str
    fm_report: "FMRefinedReport"
    sadc_results: dict[str, SADCWireResult] = field(default_factory=dict)
    sadc_promoted_count: int = 0        # FM-insecure → SADC-secure
    sadc_confirmed_insecure: int = 0    # FM-insecure → SADC-insecure (true positive)
    sadc_indeterminate_count: int = 0   # Cone too large
    sadc_not_checked_count: int = 0     # Already SECURE after D1 or FM
    sadc_time_seconds: float = 0.0
    sadc_max_cone_size: int = 16        # Threshold for INDETERMINATE

    @property
    def d1_report(self) -> "CircuitReport":
        return self.fm_report.d1_report

    def summary(self) -> str:
        return (
            f"{self.module_name}: "
            f"D1={self.d1_report.insecure_count} | "
            f"FM={self.fm_report.fm_promoted_count} promoted, "
            f"{self.fm_report.fm_indeterminate_count} residual | "
            f"SADC={self.sadc_promoted_count} promoted, "
            f"{self.sadc_confirmed_insecure} confirmed insecure, "
            f"{self.sadc_indeterminate_count} indeterminate | "
            f"{self.sadc_time_seconds:.2f}s"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "d1_insecure": self.d1_report.insecure_count,
            "fm_promoted": self.fm_report.fm_promoted_count,
            "fm_residual": self.fm_report.fm_indeterminate_count,
            "sadc_promoted": self.sadc_promoted_count,
            "sadc_confirmed_insecure": self.sadc_confirmed_insecure,
            "sadc_indeterminate": self.sadc_indeterminate_count,
            "sadc_not_checked": self.sadc_not_checked_count,
            "sadc_max_cone_size": self.sadc_max_cone_size,
            "sadc_time_seconds": self.sadc_time_seconds,
            "sadc_results": {
                name: {
                    "d1": r.d1_verdict.value,
                    "fm": r.fm_verdict.value if hasattr(r.fm_verdict, "value") else str(r.fm_verdict),
                    "sadc": r.sadc_verdict.value,
                    "mask_cone": r.mask_cone_size,
                    "r_cone": r.r_cone_size,
                    "enum_count": r.enumeration_count,
                    "time_s": round(r.sadc_time_seconds, 4),
                    "note": r.note,
                }
                for name, r in self.sadc_results.items()
            },
        }


# ============================================================================
# SADC Checker
# ============================================================================


class SADCChecker:
    """Secret-Aware Distributional Check.

    For each FM-insecure wire, runs the distributional check:
        ∃ x ≠ x' : count_{s1,r}(w(x⊕s1, s1, r) = 1) ≠ count(...)

    Implementation:
        1. Get per-bit Z3 variables for s0, s1, r in the wire's cone
        2. Introduce fresh "secret" variables for the s0 bits in cone
        3. Substitute each s0_bit with (secret_bit ⊕ s1_bit)
        4. Enumerate over all (s1_cone, r_cone) values
        5. Build count as Z3 sum
        6. Check: ∃ secret ≠ secret' : count differs (UNSAT → SECURE)
    """

    def __init__(
        self,
        query_timeout_ms: int = 30_000,
        max_cone_size: int = 16,
        module_timeout_s: float = 1800.0,
        query_rlimit: int = 20_000_000,
        random_seed: int = 0,
    ):
        """
        Args:
            query_timeout_ms: Per-wire Z3 query timeout (wall-clock fallback).
            max_cone_size: Maximum (mask + r) cone size before INDETERMINATE.
                16 bits = 65536 enumerations per secret pair (tractable).
            module_timeout_s: Total SADC pass timeout across all wires.
            query_rlimit: Z3 resource limit per query (deterministic across
                machines, unlike wall-clock timeout). Set to 0 to disable.
                20_000_000 is empirically sufficient for ≤16-bit cones on
                Adams Bridge Barrett with bit-identical results across runs.
                (Earlier 5_000_000 left one borderline ML-KEM Barrett wire
                in a non-deterministic state — the higher rlimit resolves it.)
            random_seed: Z3 SMT and SAT random seed (pinned for
                reproducibility).
        """
        self._query_timeout_ms = query_timeout_ms
        self._max_cone_size = max_cone_size
        self._module_timeout_s = module_timeout_s
        self._query_rlimit = query_rlimit
        self._random_seed = random_seed
        self._z3 = None

    def _ensure_z3(self):
        if self._z3 is None:
            import z3
            # Pin global Z3 random seeds for reproducibility. This must
            # happen before any Solver is created.
            z3.set_param("smt.random_seed", self._random_seed)
            z3.set_param("sat.random_seed", self._random_seed)
            self._z3 = z3
        return self._z3

    def check_wire(
        self,
        wire_expr: Any,
        s0_bit_vars: dict[int, Any],  # s0_index → Z3 BitVec(1)
        s1_bit_vars: dict[int, Any],  # s1_index → Z3 BitVec(1)
        r_bit_vars: dict[int, Any],   # r_index → Z3 BitVec(1)
        s0_idx_in_cone: frozenset[int],
        s1_idx_in_cone: frozenset[int],
        r_idx_in_cone: frozenset[int],
        s0_to_s1_pairing: dict[int, int],  # s0_idx → paired s1_idx (same secret)
    ) -> tuple[SADCVerdict, int, int, int, str]:
        """Run SADC on a single wire.

        Returns:
            (verdict, mask_cone_size, r_cone_size, enumeration_count, note)
        """
        z3 = self._ensure_z3()

        # Partition s0 cone: paired (reparametrize) vs unpaired (extra randomness)
        #
        # A paired s0[k] is one where s1[k] is ALSO in the cone. For these,
        # we introduce a secret variable and substitute s0[k] = secret[k] ⊕ s1[k].
        #
        # An unpaired s0[k] is one where s1[k] is NOT in the cone. From SADC's
        # perspective, s0[k] is independent uniform random (the mask alone,
        # without the secret-dependent component) — we enumerate it as randomness.
        #
        # Similarly, s1[k] bits where s0[k] is not in the cone are just masks
        # that can be enumerated directly (they already are, via s1_idx_in_cone).
        s0_paired = []      # s0 indices with paired s1 in cone (become secrets)
        s0_unpaired = []    # s0 indices without paired s1 (become randomness)
        for idx in sorted(s0_idx_in_cone):
            paired_s1 = s0_to_s1_pairing.get(idx)
            if paired_s1 is not None and paired_s1 in s1_idx_in_cone:
                s0_paired.append(idx)
            else:
                s0_unpaired.append(idx)

        mask_cone_size = len(s1_idx_in_cone)     # s1 bits (enumerate as masks)
        r_cone_size = len(r_idx_in_cone)          # fresh randomness bits
        extra_rand_size = len(s0_unpaired)        # unpaired s0 bits (enumerate as random)
        total_cone = mask_cone_size + r_cone_size + extra_rand_size
        enum_count = 2 ** total_cone if total_cone <= 30 else -1

        # Bail out if total enumeration too large
        if total_cone > self._max_cone_size:
            return (
                SADCVerdict.INDETERMINATE,
                mask_cone_size, r_cone_size, enum_count,
                f"Cone too large ({total_cone} bits > {self._max_cone_size}); "
                f"use exact tool (SILVER/Coco-Alma)"
            )

        # Create secret variables (one per paired s0/s1 position)
        secret_vars = {}
        secret_vars_p = {}
        for s0_idx in s0_paired:
            secret_vars[s0_idx] = z3.BitVec(f"sadc_sec_{s0_idx}", 1)
            secret_vars_p[s0_idx] = z3.BitVec(f"sadc_sec_p_{s0_idx}", 1)

        # Enumeration ordering
        s1_cone_sorted = sorted(s1_idx_in_cone)
        r_cone_sorted = sorted(r_idx_in_cone)
        unpaired_s0_sorted = sorted(s0_unpaired)

        count_width = max(total_cone + 1, 2)
        count = z3.BitVecVal(0, count_width)
        count_p = z3.BitVecVal(0, count_width)

        # Enumerate all (s1, r, unpaired_s0) combinations
        for s1_val in range(2 ** mask_cone_size):
            for r_val in range(2 ** r_cone_size):
                for unpaired_val in range(2 ** extra_rand_size):
                    # Build substitution list for BOTH secret and secret' queries
                    subs = []
                    subs_p = []

                    # s1 bits — fix to enumerated value
                    for bit_pos, s1_idx in enumerate(s1_cone_sorted):
                        s1_bit_val = (s1_val >> bit_pos) & 1
                        s1_var = s1_bit_vars[s1_idx]
                        s1_const = z3.BitVecVal(s1_bit_val, 1)
                        subs.append((s1_var, s1_const))
                        subs_p.append((s1_var, s1_const))

                    # Paired s0 bits — substitute with (secret ⊕ s1_val)
                    for s0_idx in s0_paired:
                        paired_s1_idx = s0_to_s1_pairing[s0_idx]
                        bit_pos = s1_cone_sorted.index(paired_s1_idx)
                        s1_bit_val = (s1_val >> bit_pos) & 1
                        s1_const = z3.BitVecVal(s1_bit_val, 1)
                        s0_var = s0_bit_vars[s0_idx]
                        subs.append((s0_var, secret_vars[s0_idx] ^ s1_const))
                        subs_p.append((s0_var, secret_vars_p[s0_idx] ^ s1_const))

                    # Unpaired s0 bits — enumerate as independent randomness
                    # (these are mask bits for secrets not in this wire's cone)
                    for bit_pos, s0_idx in enumerate(unpaired_s0_sorted):
                        unp_val = (unpaired_val >> bit_pos) & 1
                        s0_var = s0_bit_vars[s0_idx]
                        s0_const = z3.BitVecVal(unp_val, 1)
                        subs.append((s0_var, s0_const))
                        subs_p.append((s0_var, s0_const))

                    # r bits — fix to enumerated value
                    for bit_pos, r_idx in enumerate(r_cone_sorted):
                        r_bit_val = (r_val >> bit_pos) & 1
                        r_var = r_bit_vars[r_idx]
                        r_const = z3.BitVecVal(r_bit_val, 1)
                        subs.append((r_var, r_const))
                        subs_p.append((r_var, r_const))

                    w_val = z3.substitute(wire_expr, *subs)
                    w_val_p = z3.substitute(wire_expr, *subs_p)

                    count = count + z3.ZeroExt(count_width - 1, w_val)
                    count_p = count_p + z3.ZeroExt(count_width - 1, w_val_p)

        # Build the difference check
        solver = z3.Solver()
        # Pin per-solver random seed (defence-in-depth alongside global pin)
        solver.set("random_seed", self._random_seed)
        # Use rlimit (deterministic resource units) as primary bound;
        # wall-clock timeout as fallback only.
        if self._query_rlimit > 0:
            solver.set("rlimit", self._query_rlimit)
        solver.set("timeout", self._query_timeout_ms)

        if not secret_vars:
            # No paired s0/s1 secrets in cone — wire has no secret dependency
            # after reparametrization. All "share" inputs are just independent
            # random bits. The wire is SECURE by construction.
            return (
                SADCVerdict.SECURE,
                mask_cone_size, r_cone_size, enum_count,
                "No paired secrets in cone — all shares are independent randomness"
            )

        # At least one secret differs
        secret_diff = z3.Or(*[
            secret_vars[idx] != secret_vars_p[idx]
            for idx in s0_paired
        ])
        solver.add(secret_diff)
        solver.add(count != count_p)

        result = solver.check()

        note = ""
        if s0_unpaired:
            note = f"{len(s0_unpaired)} unpaired s0 bits enumerated as independent randomness"

        if result == z3.unsat:
            return (
                SADCVerdict.SECURE,
                mask_cone_size, r_cone_size, enum_count,
                note or "Distribution independent of secret"
            )
        elif result == z3.sat:
            return (
                SADCVerdict.INSECURE,
                mask_cone_size, r_cone_size, enum_count,
                note or "Distribution depends on secret (confirmed true positive)"
            )
        else:
            return (
                SADCVerdict.INDETERMINATE,
                mask_cone_size, r_cone_size, enum_count,
                "Solver timeout"
            )


# ============================================================================
# Per-bit expression builder (adapter extension)
# ============================================================================


def build_expressions_per_bit(
    adapter: "NetlistAdapter",
    multi_cycle: bool = False,
) -> tuple[
    dict,  # net_id → Z3 expression
    dict[int, Any],  # s0 index → per-bit Z3 var
    dict[int, Any],  # s1 index → per-bit Z3 var
    dict[int, Any],  # r index → per-bit Z3 var
    dict[int, int],  # s0 index → paired s1 index
]:
    """Build Z3 expressions using per-bit variables for s0, s1, r.

    Two modes:
      - Single-cycle (default): DFF Q outputs are free variables (cut points).
        Wire expressions only capture combinational logic within one cycle.
      - Multi-cycle (multi_cycle=True): DFF Q outputs are substituted with
        the combinational expression of their D pin, propagating through
        register boundaries. Matches _build_expressions_mc semantics.

    Returns:
        (expressions, s0_bit_vars, s1_bit_vars, r_bit_vars, s0_to_s1_pairing)
    """
    import z3

    # Per-bit s0 and s1 variables
    s0_bit_vars: dict[int, Any] = {}
    for idx, net_id in enumerate(adapter._s0_nets):
        s0_bit_vars[idx] = z3.BitVec(f"sadc_s0_{idx}", 1)

    s1_bit_vars: dict[int, Any] = {}
    for idx, net_id in enumerate(adapter._s1_nets):
        s1_bit_vars[idx] = z3.BitVec(f"sadc_s1_{idx}", 1)

    # Reuse adapter's r_bit_vars (already per-bit from FM infrastructure)
    r_bit_vars: dict[int, Any] = {}
    for idx, net_id in enumerate(adapter._r_nets):
        r_bit_vars[idx] = adapter._r_bit_vars[net_id]

    # Pairing: s0[k] ↔ s1[k] by positional index within each group.
    s0_to_s1_pairing: dict[int, int] = {}
    min_len = min(len(adapter._s0_nets), len(adapter._s1_nets))
    for idx in range(min_len):
        s0_to_s1_pairing[idx] = idx

    # Build net_id → Z3 expression
    expr: dict = {}
    expr["0"] = z3.BitVecVal(0, 1)
    expr["1"] = z3.BitVecVal(1, 1)
    expr["x"] = z3.BitVecVal(0, 1)

    # Primary inputs — per-bit variables
    for idx, net_id in enumerate(adapter._s0_nets):
        expr[net_id] = s0_bit_vars[idx]
    for idx, net_id in enumerate(adapter._s1_nets):
        expr[net_id] = s1_bit_vars[idx]
    for idx, net_id in enumerate(adapter._r_nets):
        expr[net_id] = r_bit_vars[idx]

    # Public inputs
    if adapter.p_width > 0:
        p_vec = z3.BitVec("sadc_p", adapter.p_width)
        for i, net_id in enumerate(adapter._p_nets):
            if adapter.p_width > 1:
                expr[net_id] = z3.Extract(i, i, p_vec)
            else:
                expr[net_id] = p_vec

    # DFF Q outputs — depends on mode
    if multi_cycle:
        # Multi-cycle: DFF Qs start as fresh vars, will be substituted later
        for q_net, dff_var in adapter._dff_vars.items():
            expr[q_net] = dff_var
    else:
        # Single-cycle: DFF Qs are cut points (fresh vars, never substituted)
        for q_net, dff_var in adapter._dff_vars.items():
            expr[q_net] = dff_var

    # Propagate through combinational cells
    expr, unknown_count = adapter._propagate_comb_expressions(expr)
    if unknown_count > 0:
        logger.warning(
            "build_expressions_per_bit: %d unknown cell outputs", unknown_count
        )

    # Multi-cycle: iteratively substitute DFF Qs with their D expressions
    # until fixpoint or layer limit. This propagates dependencies across
    # register boundaries while keeping per-bit variables.
    if multi_cycle:
        import z3 as z3mod
        max_layers = 50
        for layer in range(max_layers):
            # Build substitution: each DFF Q var → expression of its D net
            subs = []
            for name, d_net, q_net in adapter._dff_pairs:
                if d_net in expr and q_net in expr:
                    d_expr = expr[d_net]
                    q_var = adapter._dff_vars[q_net]
                    # Skip if D expression still contains the Q var (cycle)
                    if q_var.get_id() == d_expr.get_id():
                        continue
                    subs.append((q_var, d_expr))

            if not subs:
                break

            # Apply substitutions to all expressions
            changed = False
            for net_id in list(expr.keys()):
                if isinstance(net_id, str):
                    continue
                old_expr = expr[net_id]
                new_expr = z3mod.substitute(old_expr, *subs)
                if new_expr.get_id() != old_expr.get_id():
                    expr[net_id] = new_expr
                    changed = True

            if not changed:
                break

    return expr, s0_bit_vars, s1_bit_vars, r_bit_vars, s0_to_s1_pairing


# ============================================================================
# Per-wire cone analysis (SADC-specific)
# ============================================================================


def get_bit_cones(
    expr: Any,
    s0_bit_vars: dict[int, Any],
    s1_bit_vars: dict[int, Any],
    r_bit_vars: dict[int, Any],
) -> tuple[frozenset[int], frozenset[int], frozenset[int]]:
    """Extract which s0/s1/r bit indices appear in an expression's free variables.

    Returns (s0_cone, s1_cone, r_cone) as frozensets of indices.
    """
    import z3

    # Build reverse maps: Z3 var id → index
    s0_var_ids = {v.get_id(): idx for idx, v in s0_bit_vars.items()}
    s1_var_ids = {v.get_id(): idx for idx, v in s1_bit_vars.items()}
    r_var_ids = {v.get_id(): idx for idx, v in r_bit_vars.items()}

    s0_cone: set[int] = set()
    s1_cone: set[int] = set()
    r_cone: set[int] = set()

    # BFS over expression AST
    seen_ids: set[int] = set()
    stack = [expr]
    while stack:
        e = stack.pop()
        eid = e.get_id()
        if eid in seen_ids:
            continue
        seen_ids.add(eid)

        if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            if eid in s0_var_ids:
                s0_cone.add(s0_var_ids[eid])
            elif eid in s1_var_ids:
                s1_cone.add(s1_var_ids[eid])
            elif eid in r_var_ids:
                r_cone.add(r_var_ids[eid])
        else:
            for i in range(e.num_args()):
                stack.append(e.arg(i))

    return frozenset(s0_cone), frozenset(s1_cone), frozenset(r_cone)


# ============================================================================
# Top-level SADC pass
# ============================================================================


def run_sadc_pass(
    adapter: "NetlistAdapter",
    fm_report: "FMRefinedReport",
    work_items: list[tuple[int, str]],
    max_cone_size: int = 16,
    query_timeout_ms: int = 30_000,
    module_timeout_s: float = 1800.0,
    multi_cycle: bool = False,
    use_label_propagation_flags: bool = False,
) -> SADCRefinedReport:
    """Run SADC refinement on FM-insecure wires.

    Args:
        adapter: NetlistAdapter for the circuit under test.
        fm_report: FM refinement report (from CircuitVerifier with run_fm=True).
        work_items: List of (net_id, wire_name) from the D1 pass.
        max_cone_size: Maximum (mask + r) cone size for SADC (default 16 bits).
        query_timeout_ms: Per-wire Z3 timeout.
        module_timeout_s: Total SADC pass timeout.

    Returns:
        SADCRefinedReport with per-wire verdicts.
    """
    from .netlist_adapter import FMVerdict  # runtime import to avoid circular

    checker = SADCChecker(
        query_timeout_ms=query_timeout_ms,
        max_cone_size=max_cone_size,
        module_timeout_s=module_timeout_s,
    )

    # Build per-bit expressions once
    expr, s0_bit_vars, s1_bit_vars, r_bit_vars, pairing = build_expressions_per_bit(
        adapter, multi_cycle=multi_cycle
    )

    # Build name → net_id lookup
    name_to_net: dict[str, int] = {name: nid for nid, name in work_items}

    # In multi-cycle mode, the FM report's D0/D1 results come from single-cycle
    # analysis (which misses cross-register flags). Override by using label-
    # propagation to identify wires touching both share groups.
    label_prop_flagged: set[str] = set()
    if multi_cycle and use_label_propagation_flags:
        for net_id, wire_name in work_items:
            deps = adapter._input_deps.get(net_id, frozenset())
            if "s0" in deps and "s1" in deps:
                label_prop_flagged.add(wire_name)

    sadc_results: dict[str, SADCWireResult] = {}
    promoted = 0
    confirmed_insecure = 0
    indeterminate = 0
    not_checked = 0

    sadc_start = time.monotonic()

    # Determine iteration set: if using label propagation flags, iterate over
    # all work items (some of which may not be in fm_report if not SMT-flagged).
    if multi_cycle and use_label_propagation_flags:
        iter_items = [(nid, nm) for nid, nm in work_items if nm in label_prop_flagged]
    else:
        iter_items = [(name_to_net[nm], nm) for nm in fm_report.fm_results
                      if nm in name_to_net]

    for net_id, wire_name in iter_items:
        fm_wire = fm_report.fm_results.get(wire_name)

        # Module-level timeout
        if time.monotonic() - sadc_start > module_timeout_s:
            sadc_results[wire_name] = SADCWireResult(
                wire_name=wire_name,
                d1_verdict=fm_wire.d1_verdict if fm_wire else SecurityVerdict.POTENTIALLY_INSECURE,
                fm_verdict=fm_wire.fm_verdict if fm_wire else FMVerdict.NOT_CHECKED,
                sadc_verdict=SADCVerdict.INDETERMINATE,
                note="Module timeout"
            )
            indeterminate += 1
            continue

        # For SMT-based flow: only run SADC on FM-insecure wires
        # For label-propagation flow: run SADC on label-flagged wires
        if not (multi_cycle and use_label_propagation_flags):
            if fm_wire is None:
                continue
            is_fm_insecure = (
                fm_wire.d1_verdict == SecurityVerdict.POTENTIALLY_INSECURE
                and fm_wire.fm_verdict != FMVerdict.SECURE
            )
            if not is_fm_insecure:
                sadc_results[wire_name] = SADCWireResult(
                    wire_name=wire_name,
                    d1_verdict=fm_wire.d1_verdict,
                    fm_verdict=fm_wire.fm_verdict,
                    sadc_verdict=SADCVerdict.NOT_CHECKED,
                    note="Already SECURE (D1 or FM)"
                )
                not_checked += 1
                continue

        if net_id not in expr:
            sadc_results[wire_name] = SADCWireResult(
                wire_name=wire_name,
                d1_verdict=fm_wire.d1_verdict if fm_wire else SecurityVerdict.POTENTIALLY_INSECURE,
                fm_verdict=fm_wire.fm_verdict if fm_wire else FMVerdict.NOT_CHECKED,
                sadc_verdict=SADCVerdict.INDETERMINATE,
                note="Wire expression not found"
            )
            indeterminate += 1
            continue

        wire_expr = expr[net_id]

        # Analyze cone
        s0_cone, s1_cone, r_cone = get_bit_cones(
            wire_expr, s0_bit_vars, s1_bit_vars, r_bit_vars
        )

        # Run SADC
        t0 = time.monotonic()
        verdict, mcs, rcs, enum_ct, note = checker.check_wire(
            wire_expr=wire_expr,
            s0_bit_vars=s0_bit_vars,
            s1_bit_vars=s1_bit_vars,
            r_bit_vars=r_bit_vars,
            s0_idx_in_cone=s0_cone,
            s1_idx_in_cone=s1_cone,
            r_idx_in_cone=r_cone,
            s0_to_s1_pairing=pairing,
        )
        elapsed = time.monotonic() - t0

        sadc_results[wire_name] = SADCWireResult(
            wire_name=wire_name,
            d1_verdict=fm_wire.d1_verdict if fm_wire else SecurityVerdict.POTENTIALLY_INSECURE,
            fm_verdict=fm_wire.fm_verdict if fm_wire else FMVerdict.NOT_CHECKED,
            sadc_verdict=verdict,
            mask_cone_size=mcs,
            r_cone_size=rcs,
            enumeration_count=enum_ct,
            sadc_time_seconds=elapsed,
            note=note,
        )

        if verdict == SADCVerdict.SECURE:
            promoted += 1
        elif verdict == SADCVerdict.INSECURE:
            confirmed_insecure += 1
        else:
            indeterminate += 1

    sadc_elapsed = time.monotonic() - sadc_start

    return SADCRefinedReport(
        module_name=adapter.module_name,
        fm_report=fm_report,
        sadc_results=sadc_results,
        sadc_promoted_count=promoted,
        sadc_confirmed_insecure=confirmed_insecure,
        sadc_indeterminate_count=indeterminate,
        sadc_not_checked_count=not_checked,
        sadc_time_seconds=sadc_elapsed,
        sadc_max_cone_size=max_cone_size,
    )
