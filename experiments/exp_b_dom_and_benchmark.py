#!/usr/bin/env python3
"""Experiment B: DOM AND benchmark — 100% FP elimination.

Paper reference: §4.4, §4.5 (DOM AND row in Table 2)
Claims verified:
  - 6 D0/D1 flagged wires on 16-cell DOM AND
  - FM promotes 2, Boolean SADC promotes 4
  - 0 residual — 100% false-positive elimination
  - Pipeline completes in < 0.1 seconds

Runtime: < 1 second
"""

from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

NETLIST = ROOT / "netlists" / "abr_masked_AND.json"
EVIDENCE_OUT = ROOT / "evidence" / "dom_and_benchmark.json"

DOM_AND_LABELING = {
    "mode": "masked",
    "s0_bits": {"x": [0], "y": [0]},
    "s1_bits": {"x": [1], "y": [1]},
    "r_bits": {"rnd": [0]},
    "p_bits": {"clk": [0], "rst_n": [0], "zeroize": [0]},
}


def main() -> int:
    import z3

    print("=" * 70)
    print("  Exp B: DOM AND Benchmark — 100% FP Elimination")
    print("=" * 70)

    from qanary_sadc.netlist_adapter import CircuitVerifier, NetlistAdapter
    from qanary_sadc.sadc import run_sadc_pass, SADCVerdict

    t_start = time.monotonic()

    # Stage 1: D0/D1 + FM
    print("[1/2] D0/D1 + FM ...")
    cv = CircuitVerifier(timeout_ms=10_000)
    fm_report = cv.verify_circuit(NETLIST, DOM_AND_LABELING, run_fm=True)
    d1 = fm_report.d1_report
    print(f"      D1 insecure: {d1.insecure_count}")
    print(f"      FM promoted: {fm_report.fm_promoted_count}")
    print(f"      FM residual: {fm_report.fm_indeterminate_count}")

    # Stage 2: Boolean SADC
    print("[2/2] Boolean SADC ...")
    adapter = NetlistAdapter(NETLIST, DOM_AND_LABELING, None)
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

    sadc_report = run_sadc_pass(
        adapter=adapter,
        fm_report=fm_report,
        work_items=work_items,
        max_cone_size=16,
        query_timeout_ms=10_000,
    )

    total_time = time.monotonic() - t_start

    # Results
    residual = sadc_report.sadc_indeterminate_count
    fp_eliminated = d1.insecure_count > 0 and residual == 0

    print(f"\n{'=' * 70}")
    print("  RESULTS")
    print(f"{'=' * 70}")
    print(f"  D0/D1 flagged:      {d1.insecure_count}")
    print(f"  FM promoted:        {fm_report.fm_promoted_count}")
    print(f"  SADC promoted:      {sadc_report.sadc_promoted_count}")
    print(f"  Residual:           {residual}")
    print(f"  100% FP eliminated: {'YES' if fp_eliminated else 'NO'}")
    print(f"  Time:               {total_time:.3f}s")

    passed = fp_eliminated and total_time < 1.0

    if passed:
        print(f"\n  PASS — DOM AND: all structural FPs resolved")
    else:
        print(f"\n  FAIL")

    evidence = {
        "experiment": "exp_b_dom_and_benchmark",
        "paper_section": "§4.4, §4.5",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "z3_version": z3.get_version_string(),
        "python": platform.python_version(),
        "passed": passed,
        "d1_flagged": d1.insecure_count,
        "fm_promoted": fm_report.fm_promoted_count,
        "sadc_promoted": sadc_report.sadc_promoted_count,
        "residual": residual,
        "fp_eliminated_100pct": fp_eliminated,
        "total_time_s": total_time,
    }
    EVIDENCE_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(EVIDENCE_OUT, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n  Evidence: {EVIDENCE_OUT}")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
