#!/usr/bin/env python3
"""
QANARY v3.0 proof suite — full runner.

Runs T1 through T6 in order and reports a single pass/fail summary.
Each script is executed in a child Python process so a failure in one
proof does not abort the rest.

Usage:
    python3 proofs/run_all_proofs.py
    python3 proofs/run_all_proofs.py --json-out evidence/paper_proofs.json
"""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = [
    ("T2", "T2_boolean_reparametrization_round_trip.py"),
    ("T3", "T3_arithmetic_reparametrization_round_trip.py"),
    ("T4", "T4_no_overflow_assertion.py"),
    ("T5", "T5_mlkem_bias_ratio.py"),
    ("T6", "T6_small_instance_value_independence.py"),
    ("T1", "T1_value_independence_distributional.py"),
]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def run(script_name: str) -> tuple[bool, float, str]:
    path = HERE / script_name
    if not path.is_file():
        return False, 0.0, f"missing script: {path}"
    t0 = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
    )
    elapsed = (time.perf_counter() - t0) * 1000
    return proc.returncode == 0, elapsed, proc.stdout + proc.stderr


def detect_solver_versions() -> dict[str, str]:
    info: dict[str, str] = {}
    try:
        import z3
        info["z3_python"] = z3.get_version_string()
    except Exception as exc:  # pragma: no cover
        info["z3_python"] = f"unavailable ({exc})"
    sys.path.insert(0, str(HERE))
    try:
        from _proof_utils import locate_cvc5  # noqa: E402
        cvc5_bin = locate_cvc5()
        if cvc5_bin:
            info["cvc5_binary_path"] = cvc5_bin
            try:
                proc = subprocess.run(
                    [cvc5_bin, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                info["cvc5_binary_version"] = (proc.stdout or proc.stderr).splitlines()[0]
            except Exception as exc:
                info["cvc5_binary_version"] = f"unavailable ({exc})"
        else:
            info["cvc5_binary_path"] = "not found"
    except Exception as exc:
        info["cvc5_binary_path"] = f"locator error ({exc})"
    try:
        import cvc5 as cvc5_py
        info["cvc5_python"] = "available"
        if hasattr(cvc5_py, "__version__"):
            info["cvc5_python"] = cvc5_py.__version__
    except Exception:
        info["cvc5_python"] = "unavailable"
    return info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Write a machine-readable evidence snapshot to this path.",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("QANARY v3.0 formal proof suite — multi-theory SMT")
    print("=" * 70)
    print()

    results = []
    for label, script in SCRIPTS:
        ok, ms, output = run(script)
        results.append({
            "label": label,
            "script": script,
            "passed": ok,
            "wall_ms": round(ms, 2),
            "stdout_tail": output.strip().splitlines()[-1] if output.strip() else "",
        })
        marker = "PASS" if ok else "FAIL"
        print(f"  {label}: {marker:4s}  ({ms:8.1f} ms)  {script}")

    print()
    print("-" * 70)
    n_pass = sum(1 for r in results if r["passed"])
    print(f"  Suite: {n_pass} / {len(results)} proofs passed")

    suite_ok = n_pass == len(results)

    if not suite_ok:
        print()
        print("FAILED proof outputs:")
        print("=" * 70)
        for label, script in SCRIPTS:
            for r in results:
                if r["label"] == label and not r["passed"]:
                    print(f"\n--- {label} ({script}) ---")
                    # Re-run failed script to capture full output
                    _, _, full = run(script)
                    print(full)
    else:
        print("  STATUS: SUITE PROVED")

    if args.json_out is not None:
        snapshot = {
            "suite": "QANARY v3.0 formal proof suite",
            "paper": "Structural Dependency Analysis for Masked NTT Hardware (QANARY v3.0)",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "host": {
                "platform": platform.platform(),
                "python": sys.version.split()[0],
                "machine": platform.machine(),
            },
            "solvers": detect_solver_versions(),
            "scripts": [
                {
                    **r,
                    "sha256": sha256_of(HERE / r["script"]) if (HERE / r["script"]).is_file() else "missing",
                }
                for r in results
            ],
            "n_passed": n_pass,
            "n_total": len(results),
            "all_passed": suite_ok,
            "scope_statement": (
                "Algebraic backbone of §3.9 only: T2 universal over 24-bit "
                "BV; T3 universal over both ML-KEM (q=3329, w=24) and ML-DSA "
                "(q=8380417, w=24) deployed share domains; T4 universal at "
                "three configurations (ML-KEM w=24, ML-DSA w=24 deployed-"
                "tight, ML-DSA w=46 conservative bound); T5 universal over "
                "Z_3329 raw-RNG domain; T6 two-case enumeration at q=5; T1 "
                "small-domain finite expansion of Theorem 3.9.1 at q=5. "
                "Fully-universal Theorem 3.9.1 reported as future work in §6."
            ),
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(snapshot, indent=2) + "\n")
        print()
        print(f"  Evidence snapshot written: {args.json_out}")

    return 0 if suite_ok else 1


if __name__ == "__main__":
    sys.exit(main())
