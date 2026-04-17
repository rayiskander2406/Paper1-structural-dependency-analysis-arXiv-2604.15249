#!/usr/bin/env python3
"""Reproduce results from arXiv:2604.15249.

"Structural Dependency Analysis for Masked NTT Hardware:
 Scalable Pre-Silicon Verification of Post-Quantum Cryptographic Accelerators"
Ray Iskander, Khaled Kirah

Usage:
    python reproduce.py --verify   # ~1 min: check evidence files match paper claims
    python reproduce.py --quick    # ~5 min: self-checks + DOM AND + formal proofs
    python reproduce.py --full     # ~10 min: all experiments including SADC on Barrett
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def header(msg: str) -> None:
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")


def step(num: int, total: int, name: str) -> None:
    print(f"\n{Colors.BOLD}[{num}/{total}] {name}{Colors.RESET}")
    print("-" * 50)


def ok(msg: str) -> None:
    print(f"  {Colors.GREEN}PASS{Colors.RESET}  {msg}")


def fail(msg: str) -> None:
    print(f"  {Colors.RED}FAIL{Colors.RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"  {Colors.YELLOW}WARN{Colors.RESET}  {msg}")


def load_json(name: str) -> list | dict:
    path = EVIDENCE / name
    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")
    with open(path) as f:
        return json.load(f)


def run_script(script: str, timeout: int | None = None) -> bool:
    """Run a Python script as a subprocess. Returns True on success."""
    path = ROOT / script
    if not path.exists():
        warn(f"Script not found: {script}")
        return False
    cmd = [sys.executable, str(path)]
    try:
        result = subprocess.run(
            cmd, cwd=str(ROOT), timeout=timeout,
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            ok(f"{script} completed successfully")
            return True
        else:
            fail(f"{script} exited with code {result.returncode}")
            if result.stderr:
                for line in result.stderr.strip().splitlines()[-5:]:
                    print(f"         {line}")
            if result.stdout:
                for line in result.stdout.strip().splitlines()[-5:]:
                    print(f"         {line}")
            return False
    except subprocess.TimeoutExpired:
        fail(f"{script} timed out")
        return False
    except Exception as e:
        fail(f"{script} error: {e}")
        return False


# ---------------------------------------------------------------------------
# --verify mode
# ---------------------------------------------------------------------------

def verify_evidence() -> list[tuple[str, bool]]:
    """Check that evidence JSON files match key paper claims."""
    results: list[tuple[str, bool]] = []

    def check(name: str, condition: bool, detail: str = ""):
        results.append((name, condition))
        if condition:
            ok(name + (f" ({detail})" if detail else ""))
        else:
            fail(name + (f" ({detail})" if detail else ""))

    # --- SADC Barrett results ---
    step(1, 4, "SADC Barrett (evidence/sadc_barrett.json)")
    try:
        data = load_json("sadc_barrett.json")
        check(
            "Barrett: 363 D0/D1 flagged",
            data.get("d1_flagged") == 363,
            f"actual={data.get('d1_flagged')}",
        )
        check(
            "Barrett: 198 promoted secure",
            data.get("arith_sadc_promoted") == 198,
            f"actual={data.get('arith_sadc_promoted')}",
        )
        check(
            "Barrett: 165 candidate insecure",
            data.get("arith_sadc_insecure") == 165,
            f"actual={data.get('arith_sadc_insecure')}",
        )
        check(
            "Barrett: 0 indeterminate",
            data.get("arith_sadc_indeterminate") == 0,
            f"actual={data.get('arith_sadc_indeterminate')}",
        )
        if data.get("cvc5_available"):
            check(
                "Barrett: 0 CVC5 disagreements",
                data.get("cvc5_disagreements") == 0,
                f"actual={data.get('cvc5_disagreements')}",
            )
    except FileNotFoundError:
        check("sadc_barrett.json exists", False)

    # --- DOM AND benchmark ---
    step(2, 4, "DOM AND benchmark (evidence/dom_and_benchmark.json)")
    try:
        data = load_json("dom_and_benchmark.json")
        check(
            "DOM AND: 100% FP elimination",
            data.get("fp_eliminated_100pct") is True,
            f"residual={data.get('residual')}",
        )
    except FileNotFoundError:
        check("dom_and_benchmark.json exists", False)

    # --- Self-checks ---
    step(3, 4, "Self-checks (evidence/self_checks.json)")
    try:
        data = load_json("self_checks.json")
        check(
            "Self-checks: >= 17 checks",
            data.get("n_checks", 0) >= 17,
            f"n={data.get('n_checks')}",
        )
        check(
            "Self-checks: all pass",
            data.get("all_pass") is True,
        )
    except FileNotFoundError:
        check("self_checks.json exists", False)

    # --- Formal proofs ---
    step(4, 4, "Formal proofs (evidence/paper_proofs.json)")
    try:
        data = load_json("paper_proofs.json")
        scripts = data.get("scripts", [])
        n_pass = sum(1 for s in scripts if s.get("passed"))
        n_total = len(scripts)
        check(
            f"Formal proofs: {n_pass}/{n_total} pass",
            n_pass == n_total and n_total >= 6,
            f"{n_pass}/{n_total}",
        )
    except FileNotFoundError:
        check("paper_proofs.json exists", False)

    return results


# ---------------------------------------------------------------------------
# --quick mode
# ---------------------------------------------------------------------------

def run_quick() -> list[tuple[str, bool]]:
    """Run fast experiments (~5 min)."""
    results: list[tuple[str, bool]] = []
    scripts = [
        ("Self-Checks (17 mandatory)", "experiments/exp_c_self_checks.py", 60),
        ("DOM AND Benchmark", "experiments/exp_b_dom_and_benchmark.py", 60),
        ("Formal Proofs (T1-T6)", "proofs/run_all_proofs.py", 300),
    ]

    total = len(scripts)
    for i, (name, script, timeout) in enumerate(scripts, 1):
        step(i, total, name)
        passed = run_script(script, timeout=timeout)
        results.append((name, passed))

    return results


# ---------------------------------------------------------------------------
# --full mode
# ---------------------------------------------------------------------------

def run_full() -> list[tuple[str, bool]]:
    """Run all experiments including SADC Barrett (~10 min)."""
    results: list[tuple[str, bool]] = []
    scripts = [
        ("SADC Barrett (198/165/0)", "experiments/exp_a_sadc_barrett.py", 600),
    ]

    total = len(scripts)
    for i, (name, script, timeout) in enumerate(scripts, 1):
        step(i, total, name)
        passed = run_script(script, timeout=timeout)
        results.append((name, passed))

    return results


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(results: list[tuple[str, bool]]) -> int:
    """Print final summary table. Returns 0 if all passed, 1 otherwise."""
    n_pass = sum(1 for _, p in results if p)
    n_fail = len(results) - n_pass

    header("SUMMARY")

    for name, passed in results:
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if passed else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  [{status}]  {name}")

    print()
    if n_fail == 0:
        print(f"{Colors.BOLD}{Colors.GREEN}"
              f"  All {n_pass}/{len(results)} checks passed."
              f"{Colors.RESET}")
    else:
        print(f"{Colors.BOLD}{Colors.RED}"
              f"  {n_fail}/{len(results)} checks FAILED, "
              f"{n_pass}/{len(results)} passed."
              f"{Colors.RESET}")

    return 0 if n_fail == 0 else 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce results from arXiv:2604.15249.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify", action="store_true",
                       help="~1 min: check evidence files match paper claims")
    group.add_argument("--quick", action="store_true",
                       help="~5 min: self-checks + DOM AND + formal proofs")
    group.add_argument("--full", action="store_true",
                       help="~10 min: all experiments including SADC on Barrett")

    args = parser.parse_args()
    all_results: list[tuple[str, bool]] = []

    start = time.time()

    if args.verify:
        header("VERIFY MODE — Checking evidence files (~1 min)")
        all_results.extend(verify_evidence())

    elif args.quick:
        header("QUICK MODE — Self-checks + DOM AND + proofs (~5 min)")
        header("Phase 1: Evidence verification")
        all_results.extend(verify_evidence())
        header("Phase 2: Quick experiments")
        all_results.extend(run_quick())

    elif args.full:
        header("FULL MODE — All experiments (~10 min)")
        header("Phase 1: Evidence verification")
        all_results.extend(verify_evidence())
        header("Phase 2: Quick experiments")
        all_results.extend(run_quick())
        header("Phase 3: Full experiments (SADC Barrett)")
        all_results.extend(run_full())

    elapsed = time.time() - start
    minutes = elapsed / 60

    rc = print_summary(all_results)
    print(f"\n  Total time: {minutes:.1f} minutes\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
