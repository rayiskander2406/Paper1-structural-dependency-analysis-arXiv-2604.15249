# Paper 1 — Structural Dependency Analysis

**Title:** Structural Dependency Analysis for Masked NTT Hardware: Scalable Pre-Silicon Verification of Post-Quantum Cryptographic Accelerators

**arXiv:** [2604.15249](https://arxiv.org/abs/2604.15249) (v1 live; v2 replacement prepared — see `arxiv/v2/`)

**Zenodo:** concept DOI [10.5281/zenodo.19625392](https://doi.org/10.5281/zenodo.19625392), v1.0.0 DOI [10.5281/zenodo.19625393](https://doi.org/10.5281/zenodo.19625393)

**Authors:** Ray Iskander, Khaled Kirah

**Status:** on-arxiv (v1 published 2026-04-17; v2 replacement prepared but upload pending — see `correspondence/khaled/2026-04-17_sent_paper1_v2/`)

## Version map

| arXiv version | Status | Manuscript | Folder |
|---|---|---|---|
| v1 | LIVE | the submitted manuscript `arxiv_submission_2604.15249.docx` | `arxiv/v1/` |
| v2 | PENDING_UPLOAD | `QANARY_Paper_v2_for_Khaled_2026-04-17.docx` | `arxiv/v2/` |

## Layout

```
paper/
├── README.md                            this file
├── arxiv/
│   ├── v1/
│   │   ├── manuscript.docx              FROZEN — as uploaded 2026-04-17
│   │   └── README.md                    (minimal — only docx preserved; no markdown source)
│   └── v2/
│       ├── manuscript.docx              the pending v2 replacement
│       ├── arxiv_metadata.txt           abstract + comments field as planned
│       └── README.md
├── manuscripts/                         (empty — Paper 1 has no .md source history)
├── correspondence/
│   └── khaled/
│       ├── README.md
│       └── 2026-04-17_sent_paper1_v2/
│           ├── README.md, STATUS.md
│           └── attachments/QANARY_Paper_v2_for_Khaled.docx
├── build/                               (empty — Paper 1 had no build pipeline; docx was authored manually)
└── tex/                                 (empty — no LaTeX backup)
```

## Co-existence with artifact root

The repo root contains the **research artifact** (`evidence/`, `experiments/`, `netlists/`, `proofs/`, `src/`, `reproduce.py`) for the Zenodo deposit. The new `paper/` subtree sits alongside without disturbing any of that.

## Zenodo re-deposit consideration

Repo was renamed `qanary-structural-…` → `Paper1-structural-…` on 2026-04-18. GitHub auto-redirect keeps all old URLs alive (including the one Zenodo's web UI recorded for the v1.0.0 deposit). `.zenodo.json` never contained the GitHub URL, so the metadata itself doesn't need a patch — but the next tagged release (e.g., when paper v2 is uploaded to arXiv) will auto-mint a new Zenodo version with the new repo URL picked up by GitHub's webhook.

Recommended: bundle the next Zenodo mint with a substantive content change (e.g., v1.0.1 release when Paper 1 arXiv v2 is uploaded), rather than minting a version just for the rename.

## Standing rules

See `~/qanary/papers/registry.yaml` and `~/.claude/projects/-Users-rayiskander-qanary/memory/no-desktop-storage-version-control.md`.
