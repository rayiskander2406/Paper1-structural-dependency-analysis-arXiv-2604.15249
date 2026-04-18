# Paper 1 — Historical Archive

**Status:** ARCHIVED / READ-ONLY. Files in this folder are historical snapshots preserved for audit trail. They are **not** current build artifacts — do not modify or run them in place.

## Contents

### `qanary3.0_build_dir_2026-04-10.zip`

**Size:** ~9.3 MB, 63 files (+ 4 directory entries).
**Frozen from:** `~/Desktop/Qanary3.0/` as of 2026-04-10 17:15 (last modified).
**Archived on:** 2026-04-18.

This is the complete Word-conversion pipeline and audit-round state that produced the **`QANARY_v3.0_FOR_KHALED_REVIEW_2026-04-10_1209.docx`** delivered to Khaled ahead of the arXiv:2604.15249 v1 submission. See project memory `paper1-word-conversion.md` for the narrative of how these artifacts were used.

**What's inside (summary):**

- **Build scripts (earlier version of the Paper 3 gold-standard pipeline):**
  `build_camera_ready.py`, `build_bibliography.py`, `configure_template.py`, `convert_tables.py`, `fix_refs.py`, `format_gist.py`
- **Manuscript drafts:** `qanary_paper_v3.0_draft.md`, `qanary_paper_v3.0_camera_ready.md`
- **Audit confirmation docs (Rounds 3, 3.2, 3.4):** `CONFIRMATION_AUDIT_*.md`
- **Golden audit prompt:** `GOLDEN_AUDIT_v3_PRE_LAUNCH.md`
- **Manifest:** `MANIFEST.md`
- **Companion summary:** `GIST_AND_TECHNICAL_SUMMARY.{md,docx}`
- **Cover note to Khaled:** `NOTE_TO_KHALED.{md,docx}` (predates the 2026-04-17 v2 cover email now in `../correspondence/khaled/2026-04-17_sent_paper1_v2/cover_email.md`)
- **Gemini audit bundle:** `QANARY_v3_BUNDLE_FOR_GEMINI.md`
- **Media:** `media/` (figures used in the v3.0 manuscript)
- **Proofs:** `proofs/` (Python proof drivers used by the `v3.0` pipeline; predate the cleaned-up versions now at repo root in `../../proofs/`)

**Explicitly excluded when archiving:**
- `.DS_Store` files (macOS cruft)
- `apex-v10-cover-note-20260409.md` — a financial model cover note that was stored in the same Desktop folder but is unrelated to QANARY

## Why archived (not migrated live)

The current build pipeline lives at `../../Paper3-…/paper/build/` — Paper 3's `build_camera_ready.py` is the maintained gold-standard version and descends from the scripts captured here. Rather than integrate these older scripts into Paper 1's now-empty `paper/build/`, we archive them verbatim — they cannot be run reliably against the renamed repo paths or current pandoc conventions without rework. If a future Paper 1 v3 requires a markdown→docx rebuild, adopt Paper 3's pipeline instead (see `Paper3-…/paper/build/README.md`).

## Recovery

```bash
cd paper/_archive
unzip qanary3.0_build_dir_2026-04-10.zip
# Files land in Qanary3.0/ next to the zip. Do not commit the unzipped copy.
```
