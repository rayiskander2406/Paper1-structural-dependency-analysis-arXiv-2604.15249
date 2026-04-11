#!/usr/bin/env python3
"""Experiment C: 17 mandatory self-checks.

Paper reference: §3.5 — Self-Checks
Claims verified:
  - 17 mandatory known-answer checks validate SMT encoding
  - 7 masked Boolean + 4 unmasked + 6 arithmetic-mode circuits
  - All must pass before any target analysis

Runtime: < 10 seconds
"""

from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

EVIDENCE_OUT = ROOT / "evidence" / "self_checks.json"


def main() -> int:
    import z3

    print("=" * 70)
    print("  Exp C: 17 Mandatory Self-Checks")
    print("=" * 70)

    from qanary_sadc.probing_verifier import ProbingVerifier, VerificationMode

    t_start = time.monotonic()
    all_results = []

    pv = ProbingVerifier(timeout_ms=10_000)

    # 7 masked Boolean checks
    print("[1/3] 7 masked Boolean self-checks ...")
    bool_checks = pv.run_self_checks(VerificationMode.MASKED)
    for name, passed in bool_checks:
        status = "PASS" if passed else "FAIL"
        print(f"      [{status}] {name}")
        all_results.append({"name": name, "category": "boolean", "passed": passed})

    # 4 unmasked checks
    print("[2/3] 4 unmasked self-checks ...")
    unmask_checks = pv.run_self_checks(VerificationMode.UNMASKED)
    for name, passed in unmask_checks:
        status = "PASS" if passed else "FAIL"
        print(f"      [{status}] {name}")
        all_results.append({"name": name, "category": "unmasked", "passed": passed})

    # 6 arithmetic checks
    print("[3/3] 6 arithmetic-mode self-checks ...")
    arith_checks = pv.run_arithmetic_self_checks(n=24, q=3329)
    for name, passed in arith_checks:
        status = "PASS" if passed else "FAIL"
        print(f"      [{status}] {name}")
        all_results.append({"name": name, "category": "arithmetic", "passed": passed})

    total_time = time.monotonic() - t_start
    n_checks = len(all_results)
    n_pass = sum(1 for r in all_results if r["passed"])
    all_pass = n_pass == n_checks

    print(f"\n{'=' * 70}")
    print("  RESULTS")
    print(f"{'=' * 70}")
    print(f"  Boolean checks:    {len(bool_checks)}")
    print(f"  Unmasked checks:   {len(unmask_checks)}")
    print(f"  Arithmetic checks: {len(arith_checks)}")
    print(f"  Total:             {n_checks}")
    print(f"  All passed:        {'YES' if all_pass else 'NO'}")
    print(f"  Time:              {total_time:.3f}s")

    passed = all_pass and n_checks >= 17

    if passed:
        print(f"\n  PASS — all {n_checks} self-checks passed")
    else:
        print(f"\n  FAIL — {n_checks - n_pass} failures out of {n_checks}")

    evidence = {
        "experiment": "exp_c_self_checks",
        "paper_section": "§3.5",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "z3_version": z3.get_version_string(),
        "python": platform.python_version(),
        "passed": passed,
        "n_checks": n_checks,
        "n_boolean": len(bool_checks),
        "n_unmasked": len(unmask_checks),
        "n_arithmetic": len(arith_checks),
        "all_pass": all_pass,
        "checks": all_results,
        "total_time_s": total_time,
    }
    EVIDENCE_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(EVIDENCE_OUT, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n  Evidence: {EVIDENCE_OUT}")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
