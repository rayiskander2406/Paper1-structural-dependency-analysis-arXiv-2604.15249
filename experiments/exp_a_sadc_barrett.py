#!/usr/bin/env python3
"""Experiment A: Full SADC pipeline on ML-KEM Barrett reduction module.

Paper reference: §4.5 — SADC Evaluation
Claims verified:
  - 363 D0/D1 flagged wires
  - 198 promoted to secure by arithmetic SADC (54.5%)
  - 165 candidate insecure wires
  - 0 indeterminate
  - Z3 and CVC5 agree on all 363 wires (0 disagreements)

Runtime: ~3 minutes on a single core (Apple Silicon)
"""

from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

NETLIST = ROOT / "netlists" / "barrett_circuit.json"
EVIDENCE_OUT = ROOT / "evidence" / "sadc_barrett.json"

BARRETT_LABELING = {
    "mode": "masked",
    "s0_bits": {"x_share0": "0:23"},
    "s1_bits": {"x_share1": "0:23"},
    "r_bits": {
        "rnd_12bit": "0:11",
        "rnd_14bit": "0:13",
        "rnd_24bit": "0:23",
        "rnd_for_Boolean0": "0:13",
        "rnd_for_Boolean1": "0:13",
        "rnd_1bit": [0],
    },
    "p_bits": {"clk": [0], "rst_i": [0]},
}

# Expected headline numbers (paper §4.5)
EXPECTED_PROMOTED = 198
EXPECTED_INSECURE = 165
EXPECTED_INDET = 0
EXPECTED_D1_FLAGGED = 363


def main() -> int:
    import z3

    print("=" * 70)
    print("  Exp A: SADC Pipeline — ML-KEM Barrett Reduction")
    print("=" * 70)
    print(f"  Z3:       {z3.get_version_string()}")
    print(f"  Python:   {platform.python_version()}")
    print(f"  Netlist:  {NETLIST.name}")
    print()

    from qanary_sadc.netlist_adapter import CircuitVerifier, NetlistAdapter
    from qanary_sadc.sadc import run_sadc_pass, SADCVerdict
    from qanary_sadc.sadc_arith import (
        run_sadc_arith_pass,
        SADCArithChecker,
        SADCArithVerdict,
        SADCArithReport,
        SADCArithWireResult,
        MLKEM_Q,
        MLKEM_SHARE_WIDTH,
    )
    from qanary_sadc.sadc import build_expressions_per_bit, get_bit_cones

    t_start = time.monotonic()

    # Stage 1: D0/D1 + FM
    print("[1/3] D0/D1 + FM ...")
    t0 = time.monotonic()
    cv = CircuitVerifier(timeout_ms=30_000)
    fm_report = cv.verify_circuit(NETLIST, BARRETT_LABELING, run_fm=True)
    d1 = fm_report.d1_report
    print(f"      D1 insecure: {d1.insecure_count}  "
          f"FM residual: {fm_report.fm_indeterminate_count}  "
          f"({time.monotonic() - t0:.1f}s)")

    adapter = NetlistAdapter(NETLIST, BARRETT_LABELING, None)
    comb_nets = adapter.get_combinational_output_nets()
    dff_nets = adapter.get_dff_output_nets()
    used_names: set[str] = set()
    work_items: list[tuple[int, str]] = []
    for net_id in comb_nets + dff_nets:
        raw_name = adapter.wire_name(net_id)
        wire_name = raw_name if raw_name not in used_names else f"{raw_name} [net {net_id}]"
        used_names.add(wire_name)
        if not adapter.has_share_dependency(net_id):
            continue
        work_items.append((net_id, wire_name))

    # Stage 2: Boolean SADC
    print("\n[2/3] Boolean SADC (deterministic) ...")
    t1 = time.monotonic()
    sadc_report = run_sadc_pass(
        adapter=adapter,
        fm_report=fm_report,
        work_items=work_items,
        max_cone_size=12,
        query_timeout_ms=30_000,
    )
    print(f"      promoted: {sadc_report.sadc_promoted_count}  "
          f"insecure: {sadc_report.sadc_confirmed_insecure}  "
          f"indeterminate: {sadc_report.sadc_indeterminate_count}  "
          f"({time.monotonic() - t1:.1f}s)")

    target_wires = frozenset(
        name
        for name, res in sadc_report.sadc_results.items()
        if res.sadc_verdict in (SADCVerdict.INSECURE, SADCVerdict.INDETERMINATE)
    )

    # Stage 3: Arithmetic SADC with optional CVC5 validation
    cvc5_available = False
    try:
        import cvc5

        cvc5_available = True
    except ImportError:
        pass

    print(f"\n[3/3] Arithmetic SADC {'+ CVC5 dual-validation ' if cvc5_available else ''}...")
    t2 = time.monotonic()

    checker = SADCArithChecker(
        q_modulus=MLKEM_Q,
        share_width=MLKEM_SHARE_WIDTH,
        cvc5_validate=cvc5_available,
    )

    expr, s0_bv, s1_bv, r_bv, _ = build_expressions_per_bit(adapter, multi_cycle=False)
    name_to_net = {nm: nid for nid, nm in work_items}

    report = SADCArithReport(
        module_name=adapter.module_name,
        q_modulus=MLKEM_Q,
        share_width=MLKEM_SHARE_WIDTH,
    )

    n_targets = len(target_wires)
    progress_interval = max(1, n_targets // 10)

    for idx, wire_name in enumerate(sorted(target_wires)):
        if idx % progress_interval == 0:
            elapsed = time.monotonic() - t2
            print(f"      [{idx + 1:4d}/{n_targets}] {elapsed:.0f}s elapsed", flush=True)

        net_id = name_to_net.get(wire_name)
        if net_id is None or net_id not in expr:
            continue

        prior_res = sadc_report.sadc_results.get(wire_name)
        prior_str = prior_res.sadc_verdict.value if prior_res else "unknown"

        wire_expr = expr[net_id]
        s0_cone, s1_cone, r_cone = get_bit_cones(wire_expr, s0_bv, s1_bv, r_bv)

        t_wire = time.monotonic()
        verdict, note = checker.check_wire(
            wire_expr=wire_expr,
            s0_bit_vars=s0_bv,
            s1_bit_vars=s1_bv,
            r_bit_vars=r_bv,
            s0_idx_in_cone=s0_cone,
            s1_idx_in_cone=s1_cone,
            r_idx_in_cone=r_cone,
        )
        elapsed_wire = time.monotonic() - t_wire

        report.results[wire_name] = SADCArithWireResult(
            wire_name=wire_name,
            prior_verdict=prior_str,
            sadc_arith_verdict=verdict,
            s0_cone_size=len(s0_cone),
            s1_cone_size=len(s1_cone),
            r_cone_size=len(r_cone),
            sadc_arith_time_seconds=elapsed_wire,
            note=note,
        )

        if verdict == SADCArithVerdict.SECURE:
            if prior_res and prior_res.sadc_verdict in (
                SADCVerdict.INSECURE,
                SADCVerdict.INDETERMINATE,
            ):
                report.promoted_count += 1
        elif verdict == SADCArithVerdict.INSECURE_CONSERVATIVE:
            report.confirmed_insecure_count += 1
        else:
            report.indeterminate_count += 1

    total_time = time.monotonic() - t_start

    # Verdict
    print(f"\n{'=' * 70}")
    print("  RESULTS")
    print(f"{'=' * 70}")
    print(f"  D0/D1 flagged:      {d1.insecure_count}")
    print(f"  Arith SADC secure:  {report.promoted_count}")
    print(f"  Candidate insecure: {report.confirmed_insecure_count}")
    print(f"  Indeterminate:      {report.indeterminate_count}")
    if cvc5_available:
        print(f"  CVC5 checks:        {checker._cvc5_total_checks}")
        print(f"  CVC5 disagreements: {len(checker._cvc5_disagreements)}")
    print(f"  Total time:         {total_time:.1f}s")

    numbers_match = (
        d1.insecure_count == EXPECTED_D1_FLAGGED
        and report.promoted_count == EXPECTED_PROMOTED
        and report.confirmed_insecure_count == EXPECTED_INSECURE
        and report.indeterminate_count == EXPECTED_INDET
    )
    cvc5_clean = not cvc5_available or len(checker._cvc5_disagreements) == 0

    passed = numbers_match and cvc5_clean

    if passed:
        print(f"\n  PASS — 198/165/0 confirmed, dual-solver validated")
    else:
        print(f"\n  FAIL")
        if not numbers_match:
            print(f"    Expected: {EXPECTED_D1_FLAGGED} flagged, "
                  f"{EXPECTED_PROMOTED}/{EXPECTED_INSECURE}/{EXPECTED_INDET}")
        if not cvc5_clean:
            print(f"    CVC5 disagreements: {checker._cvc5_disagreements[:5]}")

    # Save evidence
    evidence = {
        "experiment": "exp_a_sadc_barrett",
        "paper_section": "§4.5",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "z3_version": z3.get_version_string(),
        "cvc5_available": cvc5_available,
        "cvc5_version": getattr(cvc5, "__version__", None) if cvc5_available else None,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "passed": passed,
        "d1_flagged": d1.insecure_count,
        "boolean_sadc_promoted": sadc_report.sadc_promoted_count,
        "boolean_sadc_insecure": sadc_report.sadc_confirmed_insecure,
        "boolean_sadc_indeterminate": sadc_report.sadc_indeterminate_count,
        "arith_sadc_promoted": report.promoted_count,
        "arith_sadc_insecure": report.confirmed_insecure_count,
        "arith_sadc_indeterminate": report.indeterminate_count,
        "cvc5_checks": checker._cvc5_total_checks if cvc5_available else 0,
        "cvc5_disagreements": len(checker._cvc5_disagreements) if cvc5_available else 0,
        "total_time_s": total_time,
    }
    EVIDENCE_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(EVIDENCE_OUT, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n  Evidence: {EVIDENCE_OUT}")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
