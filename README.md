# Structural Dependency Analysis for Masked NTT Hardware

[![arXiv](https://img.shields.io/badge/arXiv-2604.15249-b31b1b.svg)](https://arxiv.org/abs/2604.15249)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19625392.svg)](https://doi.org/10.5281/zenodo.19625392)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Artifact repository for reproducing results from [arXiv:2604.15249](https://arxiv.org/abs/2604.15249).
Archived on Zenodo — concept DOI: [10.5281/zenodo.19625392](https://doi.org/10.5281/zenodo.19625392) (resolves to latest version);
v1.0.0 version DOI: [10.5281/zenodo.19625393](https://doi.org/10.5281/zenodo.19625393).

## Abstract

We present a four-stage verification hierarchy --- D0/D1 structural dependency analysis, fresh-mask refinement (FM), Boolean SADC, and arithmetic SADC --- that extends sound first-order masking verification to production arithmetic modules. This artifact reproduces the central empirical result: on the 5,543-cell ML-KEM Barrett reduction module from the Adams Bridge accelerator, the pipeline machine-verifies **198 of 363 structurally-flagged wires (54.5%) as first-order secure** under arithmetic value-independence, reports **165 as candidate first-order insecure wires** for designer triage, and leaves **0 indeterminate**. Every arithmetic SADC verdict is cross-validated by Z3 and CVC5 (363 of 363 wires, 0 disagreements). A formal proof suite (T1--T6) machine-checks the algebraic backbone of the methodology.

## Quick Start

```bash
git clone https://github.com/rayiskander2406/qanary-structural-dependency-analysis-arXiv-2604.15249.git
cd qanary-structural-dependency-analysis-arXiv-2604.15249
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

# Verify pre-computed results match paper claims (~1 min)
python reproduce.py --verify

# Run self-checks + DOM AND benchmark + formal proofs (~5 min)
python reproduce.py --quick

# Run everything including full SADC Barrett pipeline (~10 min)
python reproduce.py --full
```

## Repository Structure

```
qanary-structural-dependency-analysis-arXiv-2604.15249/
├── reproduce.py                          # Main reproduction entry point
├── experiments/                          # Paper experiments
│   ├── exp_a_sadc_barrett.py             # §4.5: Full SADC pipeline on Barrett
│   ├── exp_b_dom_and_benchmark.py        # §4.4: DOM AND 100% FP elimination
│   └── exp_c_self_checks.py              # §3.5: 17 mandatory self-checks
├── proofs/                               # Formal SMT proofs
│   ├── T1_value_independence_distributional.py   # Theorem 3.9.1 finite expansion
│   ├── T2_boolean_reparametrization_round_trip.py
│   ├── T3_arithmetic_reparametrization_round_trip.py
│   ├── T4_no_overflow_assertion.py
│   ├── T5_mlkem_bias_ratio.py
│   ├── T6_small_instance_value_independence.py
│   ├── nc3_fourier_contraction.py        # NC3 gap-contraction (Fisher exact)
│   └── run_all_proofs.py                 # Run all proofs + save evidence
├── evidence/                             # Pre-computed results (JSON)
│   ├── paper_proofs.json                 # Formal proof results
│   ├── sadc_barrett.json                 # Barrett SADC evidence
│   ├── dom_and_benchmark.json            # DOM AND benchmark evidence
│   └── self_checks.json                  # Self-check evidence
├── src/qanary_sadc/                      # SADC verification pipeline
│   ├── netlist_adapter.py                # Yosys JSON → Z3 expression builder
│   ├── probing_verifier.py               # D0/D1 structural dependency queries
│   ├── sadc.py                           # Boolean SADC
│   └── sadc_arith.py                     # Arithmetic SADC + CVC5 dual-solver
├── netlists/                             # Pre-synthesized Yosys JSON netlists
│   ├── barrett_circuit.json              # ML-KEM Barrett (5,543 cells)
│   ├── butterfly_circuit.json            # NTT butterfly extraction
│   └── abr_masked_AND.json              # DOM AND reference gadget
├── pyproject.toml                        # Package configuration
├── requirements.txt                      # Pinned dependencies
├── CITATION.cff                          # Citation metadata
└── .zenodo.json                          # Zenodo deposit metadata
```

## Reproducing Paper Results

| Paper Reference | Experiment | Command | Runtime | Key Claim |
|----------------|------------|---------|---------|-----------|
| §4.5 | SADC Barrett pipeline | `python experiments/exp_a_sadc_barrett.py` | ~3 min | 198 secure / 165 insecure / 0 indet |
| §4.4 | DOM AND benchmark | `python experiments/exp_b_dom_and_benchmark.py` | < 1s | 100% FP elimination |
| §3.5 | Self-checks | `python experiments/exp_c_self_checks.py` | < 10s | 17/17 pass |
| §3.9.5 | Formal proofs (T1-T6) | `python proofs/run_all_proofs.py` | ~5s | 6/6 pass (Z3 + CVC5) |
| §3.9.5 | NC3 gap contraction | `python proofs/nc3_fourier_contraction.py` | < 1s | Fisher p = 0.0083 |

## Experiments

**Experiment A: SADC Barrett.** The central empirical result. Runs the complete four-stage hierarchy (D0/D1 → FM → Boolean SADC → Arithmetic SADC) on the 5,543-cell ML-KEM Barrett reduction module from Adams Bridge. Confirms the 198/165/0 classification and, when CVC5 is available, the 363/363 dual-solver agreement.

**Experiment B: DOM AND.** Demonstrates 100% false-positive elimination on the 16-cell DOM AND reference gadget (Gross et al., CHES 2016). The pipeline resolves all structurally-flagged wires through FM bijection and Boolean SADC value-independence.

**Experiment C: Self-Checks.** Runs the 17 mandatory known-answer checks (7 Boolean, 4 unmasked, 6 arithmetic) that validate the SMT encoding against circuits with known security properties. All must pass before any target analysis.

**Formal Proofs (T1-T6).** Machine-checked SMT proofs for the algebraic backbone of §3.9: value-independence (T1), Boolean round-trip (T2), arithmetic round-trip (T3), no-overflow (T4), ML-KEM bias ratio (T5), and small-instance worked example (T6).

## Dependencies

| Package | Version | Required | Purpose |
|---------|---------|----------|---------|
| z3-solver | >= 4.12 | Yes | SMT solving for D0/D1 and SADC queries |
| cvc5 | >= 1.2 | Optional | Dual-solver validation (if absent, Z3-only mode) |
| pytest | >= 7.0 | Dev only | Test suite |

## Hardware Requirements

- **Minimum:** 4 GB RAM, any modern CPU (for `--quick` and `--verify` modes)
- **Recommended:** 8 GB RAM (for full SADC Barrett pipeline)
- **Note:** Barrett SADC completes in ~3 minutes on Apple M2

## Target Design

The Adams Bridge ML-DSA/ML-KEM accelerator (CHIPS Alliance / Caliptra project, commit cdc9b1c) is the primary evaluation target. Pre-synthesized Yosys JSON netlists for the Barrett reduction module, NTT butterfly extraction, and DOM AND reference gadget are included in `netlists/`.

## Citation

To cite the paper:

```bibtex
@article{iskander2026structural,
  title={Structural Dependency Analysis for Masked {NTT} Hardware:
         Scalable Pre-Silicon Verification of Post-Quantum
         Cryptographic Accelerators},
  author={Iskander, Ray and Kirah, Khaled},
  year={2026},
  eprint={2604.15249},
  archivePrefix={arXiv},
  primaryClass={cs.CR}
}
```

To cite this artifact (software) — use the concept DOI so the citation always
resolves to the latest archived version:

```bibtex
@software{iskander2026structural_artifact,
  title={Artifact: Structural Dependency Analysis for Masked {NTT} Hardware},
  author={Iskander, Ray and Kirah, Khaled},
  year={2026},
  version={1.0.0},
  doi={10.5281/zenodo.19625392},
  url={https://doi.org/10.5281/zenodo.19625392},
  note={Version 1.0.0 DOI: 10.5281/zenodo.19625393}
}
```

## License

Apache 2.0. See [LICENSE](LICENSE).
