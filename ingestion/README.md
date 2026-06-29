# Ingestion

Turns official framework sources into the normalized JSON in
`../data/normalized/` that the web UI and MCP server read.

## One command

```bash
python ingestion/ingest_all.py            # downloads NIST source, builds everything
python ingestion/ingest_all.py --offline  # rebuild from already-downloaded source
```

This downloads the NIST 800-53 OSCAL catalog from the official
`usnistgov/oscal-content` repository, normalizes it (preserving the full control
hierarchy — base controls, lettered parts, and enhancements), then builds the
authored frameworks and the crosswalk spine, and validates that every risk and
mapping reference resolves.

## Scripts

| Script | Produces | Source |
|--------|----------|--------|
| `normalize_nist_oscal.py` | `nist-800-53-r5.json` | NIST official OSCAL JSON (verbatim) |
| `build_hipaa.py` | `hipaa-security-rule.json` | 45 CFR 164 (verbatim, public domain) |
| `build_owasp_nistai.py` | OWASP LLM/API/Web + NIST AI RMF/600-1 | OWASP (paraphrased), NIST (verbatim) |
| `build_crosswalk.py` | `_layers/_risks/_mappings/_index.json` | authored crosswalk spine |
| `ingest_all.py` | all of the above, in order | orchestrator |

## Provenance

The NIST 800-53 data is not hand-typed — it is normalized directly from NIST's
machine-readable source, so it can be re-verified against the publication at any
time. The `framework.source_checksum` field records a hash of the raw source so
the validation agent (Chunk 5) can detect when a publication has changed.

See `../docs/SOURCING-POLICY.md` for how each framework's content is handled
(verbatim / paraphrased / own-wording) and `../docs/DATA-MODEL.md` for the schema.
