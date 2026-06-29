# Contributing to Kyora IQ

Thanks for helping build an open compliance reference. The most valuable
contributions are accurate data and well-sourced cross-framework mappings.

## Ground rules

1. **Respect sourcing buckets.** Every framework is handled as verbatim,
   paraphrased, or own-wording per `docs/SOURCING-POLICY.md`. Never paste long
   passages from a licensed (Bucket 3) source. When in doubt, write your own
   description and link to the official text.
2. **Mappings are claims.** A mapping asserts two controls address the same
   concern. Mark official-crosswalk mappings with that crosswalk's name as
   `source`; mark your own as `source: "kyora-iq"` with a one-line `rationale`.
3. **Data is generated, not hand-edited.** Don't edit files in
   `data/normalized/` directly — change the ingestion script and re-run, so the
   data stays reproducible.
4. **Validation must pass.** Run `python validation/validate.py` before opening a
   PR; CI runs it too.

## Adding a framework

1. Decide the sourcing bucket and add the framework to `README.md` and
   `NOTICE.md`.
2. Write a builder in `ingestion/` that emits `data/normalized/<framework-id>.json`
   matching `docs/DATA-MODEL.md` (hierarchical controls, `layer` on each,
   framework-specific `attributes`).
3. Wire it into `ingestion/ingest_all.py`.
4. Add cross-framework mappings in `ingestion/build_crosswalk.py` (with relation,
   strength, source, rationale). Reference controls as `"<framework-id>:<control-id>"`.
5. Rebuild and validate:
   ```bash
   python ingestion/ingest_all.py
   python scripts/build_web_bundle.py
   python validation/validate.py
   ```

## Adding a source-drift check

If your framework has a machine-readable source or a stable version signal, add a
`check_source_<framework>()` to `validation/validate.py` so drift is caught
automatically — same pattern as the NIST check.

## Style

Python: standard library where possible; the MCP SDK is the only runtime
dependency. Keep builders deterministic so re-runs produce identical output.
