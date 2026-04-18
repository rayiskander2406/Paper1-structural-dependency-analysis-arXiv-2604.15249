# arXiv v2 — pending upload

**Source:** `manuscript.docx` (= the `QANARY_Paper_v2_for_Khaled_2026-04-17.docx` that was prepared for Khaled's sanity-check + upload on 2026-04-17)
**Status:** awaiting Khaled to upload as arXiv v2 replacement of 2604.15249

## Planned metadata changes (per `arxiv_metadata.txt`)

The `arxiv_metadata.txt` in this folder is the literal text to paste into arXiv's "Submit a new version" form:

- **Abstract** — revised opening sentence to reference "PQC", "ML-KEM (FIPS 203)", "ML-DSA (FIPS 204)" explicitly. Rest of abstract unchanged from v1.
- **Comments field** — `v2: added Zenodo artifact DOI (10.5281/zenodo.19625392); minor abstract revision to reference FIPS 203/204 explicitly; resolved artifact-repository URL placeholder in the Code and Data Availability section. No changes to the methodology, results, or references.`

Note: the Comments field text currently references `10.5281/zenodo.19625392` which is **Paper 1's own** Zenodo concept DOI. Confirm that's intentional (it's the right DOI for this paper's archive) — just flagging because the cross-reference to **Paper 2**'s Zenodo (`19508454`) is a different concern and belongs in the Code and Data Availability body of the manuscript, not the Comments field.

## Files

| File | Purpose |
|---|---|
| `manuscript.docx` | The v2 replacement docx to upload (copy of what was sent to Khaled) |
| `arxiv_metadata.txt` | Abstract + comments field text as planned |

## On upload (Khaled action)

1. Open `manuscript.docx` in Word, click **References → Update Citations and Bibliography** once to refresh any stale in-text cached numbers
2. Submit as arXiv v2 replacement of 2604.15249, updating Abstract and Comments fields per `arxiv_metadata.txt`
3. Update `../README.md` table to move v2 from PENDING_UPLOAD to LIVE
4. Update `correspondence/khaled/2026-04-17_sent_paper1_v2/STATUS.md` from PENDING to ARXIV_V2_UPLOADED
5. Tag the repo as `arxiv-v2`
6. A new Zenodo version should auto-mint via the GitHub webhook — verify
7. Update `~/qanary/papers/registry.yaml` `papers.paper1.arxiv.versions[]` append v2 entry
