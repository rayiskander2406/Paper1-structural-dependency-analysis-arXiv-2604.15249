"""
Shared utilities for the QANARY v3.0 proof suite.

Provides:
  - locate_cvc5(): finds the CVC5 binary across the standard locations
    used by Paper 2's proof scripts.
  - cvc5_check_smtlib(text): runs a CVC5 query on an SMT-LIB2 string.
"""

import os
import shutil
import subprocess
import tempfile
import time
from typing import Tuple


def locate_cvc5() -> str:
    """Return path to cvc5 binary, or empty string if unavailable."""
    cvc5 = os.environ.get("CVC5_BINARY", "") or shutil.which("cvc5") or ""
    if cvc5 and os.path.isfile(cvc5):
        return cvc5
    for candidate in [
        os.path.expanduser("~/bin/cvc5"),
        "/usr/local/bin/cvc5",
        "/opt/homebrew/bin/cvc5",
        "/tmp/cvc5-gpl/cvc5-macOS-arm64-static-gpl/bin/cvc5",
    ]:
        if os.path.isfile(candidate):
            return candidate
    return ""


def cvc5_check_smtlib(smt2_text: str, timeout_s: int = 60) -> Tuple[str, float]:
    """Run CVC5 on an SMT-LIB2 query string. Returns (result, elapsed_ms)."""
    cvc5 = locate_cvc5()
    if not cvc5:
        return "skipped (cvc5 not found)", 0.0
    if "(check-sat)" not in smt2_text:
        smt2_text = smt2_text + "\n(check-sat)\n"
    with tempfile.NamedTemporaryFile("w", suffix=".smt2", delete=False) as f:
        f.write(smt2_text)
        path = f.name
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [cvc5, "--lang=smt2", path],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return "timeout", (time.perf_counter() - t0) * 1000
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    elapsed = (time.perf_counter() - t0) * 1000
    # CVC5 may emit warnings (e.g., "no logic set") interleaved with the
    # check-sat result. Scan for the first sat/unsat/unknown token. We
    # require an exact-line match (line.strip() == token) so that warning
    # messages containing the substring "unsat" do NOT trigger a false
    # positive. We also surface non-zero exit codes explicitly so that a
    # CVC5 crash never silently looks like a successful proof.
    combined = proc.stdout + "\n" + proc.stderr
    for token in ("unsat", "sat", "unknown"):
        for line in combined.splitlines():
            if line.strip() == token:
                return token, elapsed
    if proc.returncode != 0:
        return f"error (exit code {proc.returncode})", elapsed
    last = [ln for ln in combined.strip().splitlines() if ln.strip()]
    return (last[-1] if last else "no-output"), elapsed
