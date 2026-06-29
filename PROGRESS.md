# Kyora IQ — Build Progress

This file is the resume point. If a session ends, open this first to see what is
done and what is next. Each chunk writes real files before the next begins.

## Decisions locked

- Product: Kyora IQ MCP Compliance Control Reference (separate from Nemesis).
- Not AI-only: full security/privacy/AI framework coverage (13 frameworks).
- Primary view: search-primary, returning controls + cross-framework mappings.
- Secondary view: layer filter (Input/Output/Model/Infrastructure/Agentic/Governance).
- Detail interaction: inline drop-down expansion (not side panel).
- Header/content: left-aligned.
- Design language: dark enterprise, inspired by Nemesis's look (not its content).
- Frameworks ingested in waves (1: 7 clean+OWASP, 2: MITRE, 3: licensed).
- Data model: hierarchical control tree, framework-specific attributes,
  mappings as first-class records with relation + strength. See docs/DATA-MODEL.md.

## Chunk status

- [x] Chunk 0 — Project map (README, DATA-MODEL, SOURCING-POLICY, this file)
- [x] Chunk 1 — All-13-framework normalized data (2347 nodes) + 8 risks + 31 mappings + layers
- [x] Chunk 2 — Ingestion scripts (NIST normalizer + builders + ingest_all orchestrator, reproducible)
- [x] Chunk 3 — Web interface (search-primary, inline expand, left-aligned, functionally tested)
- [x] Chunk 4 — MCP server (6 tools, tested with a real MCP client over streamable HTTP)
- [x] Chunk 5 — Validation agent (integrity + live NIST source-drift detection, CI workflow, drift-catch verified)
- [x] Chunk 6 — Open-source packaging (LICENSE, NOTICE, requirements, CONTRIBUTING, CI, bundle script)

## Phase 1 build: COMPLETE (wave 1). Remaining: wave 2 (MITRE), wave 3 (licensed frameworks).

## Wave status (data ingestion)

- [x] Wave 1: NIST 800-53, NIST AI RMF, NIST AI 600-1, HIPAA, OWASP LLM/API/Web
- [x] Wave 2: MITRE ATLAS (official YAML, 16 tactics/127 nodes), MITRE ATT&CK (curated subset)
- [x] Wave 3: SOC 2 (full criteria), ISO 42001 (Annex A objectives), EU AI Act (own wording)

## ALL 13 FRAMEWORKS INGESTED. 2347 nodes, 8 risks, 31 mappings, 33 validation checks pass.
## Phase 3 step 1 DONE: gateway (config-driven bind, bearer auth, rate limit, /health, deploy config, student guide).
## Remaining: full gateway (prompt-injection filter, audit logging) — optional.

## Notes for next session

- Normalized data is the source of truth the web UI and MCP server both read.
- For NIST, prefer ingesting from official OSCAL JSON to inherit the hierarchy.
- Wave 1 also establishes the canonical risk list and the six layers.
