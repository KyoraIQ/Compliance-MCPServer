# Kyora IQ — Sourcing & Licensing Policy

Kyora IQ reproduces framework content only as each source's license permits.
Every framework falls into one of three buckets, and every normalized file
records its bucket in `framework.source_handling`. This policy is also surfaced
in the UI so users know exactly what they are reading.

## Bucket 1 — Verbatim (public domain)

Reproduced word-for-word from the official source.

- **NIST SP 800-53 Rev. 5** — U.S. Government work, public domain. Ingested from
  NIST's official machine-readable OSCAL JSON (the `usnistgov/oscal-content`
  repository), which also gives us the control hierarchy for free.
- **NIST AI RMF (AI 100-1)** and **NIST AI 600-1** — U.S. Government work,
  public domain.
- **HIPAA Security Rule (45 CFR Part 164)** — U.S. federal regulation, public
  domain (Code of Federal Regulations). The Required/Addressable flags are part
  of the regulation and are captured as attributes.

## Bucket 2 — Paraphrased with attribution

The license permits reuse with attribution and share-alike, but we still write
our own concise descriptions rather than copying long passages.

- **OWASP Top 10 for LLM Applications**, **OWASP API Security Top 10**,
  **OWASP Top 10 (Web)** — © OWASP, CC BY-SA 4.0. We carry the official
  identifiers (e.g. `LLM01:2025`, `API1:2023`, `A01:2021`) and titles verbatim
  (identifiers and short titles are facts), and paraphrase descriptions.
  Attribution and a link to the source are stored on each framework record.
- **MITRE ATLAS**, **MITRE ATT&CK** — © The MITRE Corporation, used under
  MITRE's terms with attribution. Technique IDs and names are carried;
  descriptions are paraphrased.

## Bucket 3 — Own wording (licensed source text)

The official text is copyrighted and sold, so we reproduce **only the structure
and identifiers** (which are facts) and write **entirely our own plain-language
descriptions**, plus mappings to controls we are allowed to publish.

- **SOC 2 / AICPA Trust Services Criteria** — criteria IDs (CC1.1, CC6.1, …) and
  category structure only; descriptions are Kyora IQ's own wording.
- **ISO/IEC 42001** — annex control numbers and titles structure only; our own
  descriptions.
- **EU AI Act** — Article/Annex references (the law text itself is public, but we
  summarize rather than reproduce long passages, and link to the official OJ text).

## Mappings provenance

Cross-framework mappings carry their own `source`:

- `source: "<official-crosswalk-name>"` when taken from a published crosswalk
  (e.g. NIST's HIPAA Security Rule ↔ 800-53 mapping, or NIST's CSF/PF crosswalks).
- `source: "kyora-iq"` when hand-authored. These are clearly labeled in the UI as
  Kyora IQ's interpretation, not the standards body's official position.

## What we never do

- Reproduce long verbatim passages from Bucket 3 sources.
- Present a hand-authored mapping as if it were an official crosswalk.
- Imply Kyora IQ output is a compliance certification or legal advice.

## Attribution block (rendered in UI footer and API responses)

> Framework content: NIST and HIPAA reproduced from public-domain U.S.
> Government sources. OWASP content © OWASP Foundation (CC BY-SA 4.0). MITRE
> ATLAS/ATT&CK © The MITRE Corporation. SOC 2 (AICPA), ISO/IEC 42001, and
> are described in Kyora IQ's own words; their official texts are
> copyrighted by the respective bodies. Mappings marked "Kyora IQ" are our own
> interpretation. Kyora IQ is a reference, not a certification or legal advice.
