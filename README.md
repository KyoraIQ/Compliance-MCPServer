# Kyora IQ — MCP Compliance Control Reference

A searchable, cross-framework reference for security, privacy, and AI-governance
controls — built to be queried both by humans (web UI) and by AI assistants
(over the Model Context Protocol).

You search a risk, control, or keyword once, and Kyora IQ returns the relevant
controls with every **related control in every other framework** shown alongside.
The same normalized data powers a web interface and an MCP server, so an AI
assistant can pull authoritative, cited control text instead of guessing.

> **What this is:** a trustworthy *reference* — the rulebook.
> **What this is not (yet):** an automated audit of your environment. An AI
> assistant can *use* this reference while reviewing a system, but the checking
> of a real environment is a separate, later capability.

## Frameworks tracked (13)

Ingested in waves. Each framework is handled according to how its source is
licensed — see `docs/SOURCING-POLICY.md`.

| Wave | Framework | Source handling |
|------|-----------|-----------------|
| 1 | NIST SP 800-53 Rev. 5 | Verbatim (public domain, official OSCAL JSON) |
| 1 | NIST AI RMF (AI 100-1) | Verbatim (public domain) |
| 1 | NIST AI 600-1 (Generative AI Profile) | Verbatim (public domain) |
| 1 | HIPAA Security Rule (45 CFR 164) | Verbatim (public domain, US regulation) |
| 1 | OWASP Top 10 for LLM Applications | Paraphrased + attributed (CC BY-SA) |
| 1 | OWASP API Security Top 10 | Paraphrased + attributed (CC BY-SA) |
| 1 | OWASP Top 10 (Web) | Paraphrased + attributed (CC BY-SA) |
| 2 | MITRE ATLAS | Paraphrased + attributed (MITRE terms) |
| 2 | MITRE ATT&CK | Paraphrased + attributed (MITRE terms) |
| 3 | SOC 2 / AICPA Trust Services Criteria | Own wording (AICPA text licensed) |
| 3 | ISO/IEC 42001 | Own wording (ISO text licensed) |
| 3 | EU AI Act | Article references + own summaries |

## Crosswalk

Controls are grouped into **control domains** so you can see how the same theme
is addressed across every framework at once. There are 28 domains: 12 covering
general security and privacy (access control, audit logging, encryption, risk
assessment, incident response, and so on) and 16 covering AI-specific security
risks across the five AI layers (input, output, model, infrastructure, agentic),
including prompt injection, sensitive information disclosure, model theft,
unbounded consumption, excessive agency, and MCP and connector tool abuse.

Cross-framework **mappings** connect individual controls to their equivalents in
other frameworks. Mappings are hand-authored Kyora IQ interpretations, clearly
tagged as such, and the community can suggest more through a pre-filled GitHub
issue from any control's page. Mappings are not official crosswalks; they are a
reasoned starting point, the same way any GRC team builds its own.

## Repository layout

```
kyora-iq/
  data/
    raw/          downloaded source files (gitignored; reproduced by ingestion)
    normalized/   the canonical normalized JSON the whole project reads
  ingestion/      scripts that turn official sources into normalized JSON
  web/            the human-facing site (search-primary, inline expand)
  server/         the MCP server (tools over Model Context Protocol)
  validation/     agent that re-checks normalized data against current sources
  docs/           data model, sourcing policy, architecture
  mockups/        static HTML design prototypes
```

## Build chunks

Each chunk ends with files saved to disk so work is never lost mid-build.

- **Chunk 0** — Project map: this README, PROGRESS, data model, sourcing policy.
- **Chunk 1** — Real data, wave 1 (7 frameworks) normalized to the schema.
- **Chunk 2** — Ingestion scripts that reproduce wave-1 data from official sources.
- **Chunk 3** — Web interface (search-primary, inline drop-down detail, left-aligned).
- **Chunk 4** — MCP server exposing the data as tools.
- **Chunk 5** — Validation agent (re-checks data vs. current publications).
- **Chunk 6** — Open-source packaging (license, sourcing statement, deploy docs).

## Phases (product arc beyond this build)

- **Phase 1** — Trustworthy, searchable, AI-connectable reference (this build).
- **Phase 2** — More frameworks, richer mappings, optional environment checks.
- **Phase 3** — Security hardening: gateway + authorization in front of the server.

## License

See `LICENSE` (code) and `docs/SOURCING-POLICY.md` (data/content). Code is
open source; framework content follows each source's license as documented.
