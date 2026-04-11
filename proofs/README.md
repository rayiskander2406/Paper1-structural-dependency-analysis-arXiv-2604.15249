# Formal Proof Suite

Machine-checked SMT proofs for the algebraic backbone of §3.9 (SADC).

| Proof | Description | Solver |
|-------|-------------|--------|
| T1 | Value-independence distributional security (small-domain finite expansion, q=5) | CVC5 (universal), Z3 (cross-check) |
| T2 | Boolean reparametrization round-trip: (x ⊕ s₁) ⊕ s₁ = x (24-bit) | Z3 + CVC5 |
| T3 | Arithmetic reparametrization round-trip: URem(URem(x - s₁ + q, q) + s₁, q) = x | Z3 + CVC5 |
| T4 | No-overflow assertion: 1 ≤ (x - s₁ + q) < 2q < 2^w | Z3 + CVC5 |
| T5 | ML-KEM bias ratio: max bias = 2 for raw 12-bit → Z₃₃₂₉ | Python + Z3/CVC5 |
| T6 | Small instance value independence + converse gap (q=5) | Z3 + CVC5 |
| NC3 | Gap-contraction proof (Fisher's exact test on ablation data) | Statistical |

## Running

```bash
# All proofs
python proofs/run_all_proofs.py

# Individual proof
python proofs/T2_boolean_reparametrization_round_trip.py
```

## Requirements

- Z3 (Python package `z3-solver`)
- CVC5 binary in PATH or Python package `cvc5`
