# Kyora IQ — Data Model

This is the canonical schema every part of the project reads and writes. It is
designed around three facts about real compliance frameworks:

1. **Controls are hierarchical.** A control can contain nested children to
   arbitrary depth (NIST AC-2 → enhancement AC-2(1) → part a. → sub-part a.1;
   HIPAA standard → implementation specification).
2. **Each framework nests differently and carries its own attributes.** HIPAA
   specs are flagged Required/Addressable; NIST distinguishes base controls from
   enhancements; SOC 2 criteria have points of focus. The schema must preserve
   these without flattening them into a lossy common shape.
3. **Mappings are relationships, not bare ID lists.** A mapping has a direction
   and a match strength, and is itself a first-class record.

## Two top-level collections

### 1. `controls` — one normalized file per framework

Each framework normalizes to `data/normalized/<framework_id>.json`:

```jsonc
{
  "framework": {
    "id": "nist-800-53-r5",
    "name": "NIST SP 800-53 Rev. 5",
    "version": "5.2.0",
    "publisher": "NIST",
    "source_handling": "verbatim",       // verbatim | paraphrased | own-wording
    "source_url": "https://...",
    "license": "public-domain",
    "retrieved_at": "2026-06-25",
    "source_checksum": "sha256:..."       // of the raw source, for validation
  },
  "controls": [ Control, Control, ... ]
}
```

A `Control` node (recursive):

```jsonc
{
  "id": "ac-2",                 // stable, lowercased, framework-unique
  "display_id": "AC-2",         // as printed in the source
  "title": "Account Management",
  "kind": "control",            // control | enhancement | standard | spec | criterion | risk | technique
  "statement": "….",            // the normative text (verbatim where allowed)
  "guidance": "….",             // discussion / supplemental guidance (optional)
  "layer": "infrastructure",    // see Layers below (nullable for pure-governance)
  "attributes": {               // framework-specific, free-form but documented
    "family": "Access Control",
    "baseline": ["low","moderate","high"]
  },
  "children": [ Control, ... ], // nested parts / enhancements / specs
  "mappings": [ Mapping, ... ], // cross-framework relationships (see below)
  "source_ref": "ac-2",         // id/anchor in the raw source, for traceability
  "source_handling": "verbatim" // inherited unless overridden per-node
}
```

Framework-specific attribute conventions (documented, not enforced by shape):

- **HIPAA**: `attributes.requirement = "required" | "addressable"`,
  `attributes.section = "164.312(a)(1)"`.
- **NIST 800-53**: `attributes.family`, `attributes.baseline`,
  `kind = "enhancement"` for AC-2(1)-style nodes.
- **SOC 2**: child nodes with `kind = "point_of_focus"`.
- **OWASP**: child nodes for `common_examples`, `prevention`, `attack_scenarios`
  carried as `kind = "section"` with the section name in `title`.
- **NIST AI RMF**: `attributes.function = "GOVERN|MAP|MEASURE|MANAGE"`.

### 2. `mappings` — relationships between controls

Stored inline on each control's `mappings[]`, and also compiled into a single
`data/normalized/_mappings.json` index for fast crosswalk lookups.

```jsonc
{
  "to_framework": "hipaa-security-rule",
  "to_control": "164.312(a)(1)",
  "to_title": "Access Control",
  "relation": "equivalent",     // equivalent | broader | narrower | related
  "strength": "strong",         // strong | partial | weak
  "rationale": "Both require enforcing access to authorized identities.",
  "source": "nist-hipaa-crosswalk" // provenance of the mapping itself
}
```

Mappings are stored once and rendered bidirectionally by the apps. Where an
official crosswalk exists (e.g. NIST's HIPAA↔800-53), `source` records it;
hand-authored mappings are marked `source: "kyora-iq"` and are clearly our own
interpretation, not the standards body's.

## Layers (the crosswalk spine)

Every control is tagged with the layer of a stack it primarily concerns. Used by
the web UI's layer filter and to group crosswalk results.

| id | label | covers |
|----|-------|--------|
| `input` | Input | prompts, RAG context, files, request inputs |
| `output` | Output | model/system responses and downstream handling |
| `model` | Model | the model, training data, embeddings |
| `infrastructure` | Infrastructure | APIs, keys, hosting, rate limits, accounts |
| `agentic` | Agentic | tools, autonomy, multi-step agent actions |
| `governance` | Governance | policy, risk management, accountability, lifecycle |

A control may be primarily one layer; controls that genuinely span layers carry
`attributes.secondary_layers = [...]`. Pure policy controls (much of NIST AI RMF,
ISO 42001) use `governance`.

## Risks (canonical risk list)

The crosswalk's organizing concept. A small canonical set of risks (seeded from
the OWASP LLM Top 10 plus classic security risks) lives in
`data/normalized/_risks.json`:

```jsonc
{
  "id": "prompt-injection",
  "title": "Prompt Injection",
  "layer": "input",
  "summary": "Crafted input overrides intended instructions…",
  "controls": [ { "framework": "...", "control": "..." }, ... ]
}
```

Risks link out to controls; controls do not own risks. This keeps the risk list
curated and stable while controls are ingested per framework.

## Identity & stability rules

- `framework.id` is a stable kebab-case slug; never reused.
- `control.id` is unique within its framework, lowercased, punctuation→`-`.
- A global control reference is `"<framework_id>:<control_id>"`, e.g.
  `nist-800-53-r5:ac-2`. Mappings and risks use this form internally.
- Re-ingestion must preserve ids so mappings and bookmarks stay valid.

## Validation expectations (used by Chunk 5)

- Every `to_control` in a mapping must resolve to a real control id.
- Every risk's `controls[]` must resolve.
- `source_checksum` lets the validation agent detect when a published source has
  changed since `retrieved_at`.
