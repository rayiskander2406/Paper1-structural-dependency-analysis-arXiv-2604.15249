PENDING

Last updated: 2026-04-18 (no response yet; upload not observed on arXiv)

## State machine

- 2026-04-17 — SENT (v2 replacement docx + arxiv_metadata.txt passed to Khaled for sanity-check + upload)
- → next expected: ARXIV_V2_UPLOADED (verify by checking arxiv.org/abs/2604.15249v2)

## On Khaled's response

- If he uploads directly: update STATUS to `ARXIV_V2_UPLOADED`; freeze upload bytes into `../../../arxiv/v2/manuscript.docx` (already populated from the attachment); write real upload date + arxiv URL into `../../../arxiv/v2/README.md`; tag repo `arxiv-v2`; update registry; verify Zenodo auto-mints a new version
- If he asks questions or sends edits: create `2026-04-DD_received_*` folder with his message + STATUS update
