"""
Build the crosswalk spine that ties the per-framework files together:
  - data/normalized/_layers.json    the six layers
  - data/normalized/_risks.json     canonical risks -> linked controls
  - data/normalized/_mappings.json  cross-framework control mappings (bidirectional)
  - data/normalized/_index.json     manifest of frameworks + counts

Mappings are authored here with relation + strength + provenance per the data
model. Where a public official crosswalk exists, source names it; otherwise the
mapping is marked source "kyora-iq" (our interpretation).

Run (after the per-framework files exist):
  python ingestion/build_crosswalk.py data/normalized
"""
from __future__ import annotations
import json, sys, datetime
from pathlib import Path

LAYERS = [
    {"id": "input", "label": "Input", "covers": "Prompts, RAG context, files, and request inputs that reach the system."},
    {"id": "output", "label": "Output", "covers": "Model and system responses and how they are handled downstream."},
    {"id": "model", "label": "Model", "covers": "The model itself, training data, and embeddings."},
    {"id": "infrastructure", "label": "Infrastructure", "covers": "APIs, keys, hosting, accounts, and rate limits around the system."},
    {"id": "agentic", "label": "Agentic", "covers": "Tools, autonomy, and multi-step actions an agent can take."},
    {"id": "governance", "label": "Governance", "covers": "Policy, risk management, accountability, and lifecycle controls."},
]

# Canonical risks (seeded from OWASP LLM + classic security). Each links to
# controls across frameworks using "<framework_id>:<control_id>" refs.
# Control DOMAINS — the general crosswalk spine. Each domain is a common
# compliance theme, with the equivalent control in each framework that has one.
# This is framework-general (not AI-specific); AI domains are included among them.
# Stored under the "risks" key for data-model compatibility; rendered as "domains".
RISKS = [
    {"id": "access-control", "title": "Access Control & Authorization", "layer": "infrastructure",
     "summary": "Restricting access to systems and data to authorized identities, and enforcing least privilege.",
     "controls": ["nist-800-53-r5:ac-3", "nist-800-53-r5:ac-6", "hipaa-security-rule:312-a-1",
                  "soc2-tsc:cc6", "hitrust-csf:01", "owasp-web-top10:a01-2021",
                  "owasp-api-top10:api1-2023", "mitre-attack:t1078"]},
    {"id": "identity-authentication", "title": "Identity & Authentication", "layer": "infrastructure",
     "summary": "Verifying the identity of users and services before granting access.",
     "controls": ["nist-800-53-r5:ia-2", "hipaa-security-rule:312-d", "soc2-tsc:cc6",
                  "hitrust-csf:01", "owasp-web-top10:a07-2021", "owasp-api-top10:api2-2023",
                  "mitre-attack:t1556"]},
    {"id": "audit-logging", "title": "Audit Logging & Monitoring", "layer": "infrastructure",
     "summary": "Recording and reviewing security-relevant events to detect and investigate activity.",
     "controls": ["nist-800-53-r5:au-2", "hipaa-security-rule:312-b", "soc2-tsc:cc7",
                  "hitrust-csf:09", "owasp-web-top10:a09-2021", "eu-ai-act:art-12",
                  "mitre-attack:t1070"]},
    {"id": "encryption", "title": "Encryption & Data Protection", "layer": "infrastructure",
     "summary": "Protecting data in transit and at rest with cryptographic controls.",
     "controls": ["nist-800-53-r5:sc-8", "hipaa-security-rule:312-e-1", "soc2-tsc:cc6",
                  "hitrust-csf:10", "owasp-web-top10:a02-2021"]},
    {"id": "risk-assessment", "title": "Risk Assessment & Management", "layer": "governance",
     "summary": "Identifying, analyzing, and treating risks to systems, data, and objectives.",
     "controls": ["nist-800-53-r5:ra-3", "hipaa-security-rule:308-a-1", "soc2-tsc:cc3",
                  "hitrust-csf:03", "iso-42001:a5", "nist-ai-rmf:map-1-1", "eu-ai-act:art-9"]},
    {"id": "incident-response", "title": "Incident Response", "layer": "governance",
     "summary": "Detecting, responding to, and recovering from security incidents.",
     "controls": ["nist-800-53-r5:ir-4", "hipaa-security-rule:308-a-6", "soc2-tsc:cc7",
                  "hitrust-csf:11"]},
    {"id": "change-management", "title": "Change & Configuration Management", "layer": "infrastructure",
     "summary": "Controlling changes to systems, software, and configurations.",
     "controls": ["nist-800-53-r5:cm-3", "soc2-tsc:cc8", "hitrust-csf:09",
                  "owasp-web-top10:a08-2021"]},
    {"id": "asset-management", "title": "Asset & Data Classification", "layer": "governance",
     "summary": "Inventorying assets and classifying data by sensitivity.",
     "controls": ["nist-800-53-r5:cm-8", "soc2-tsc:cc6", "hitrust-csf:07"]},
    {"id": "vulnerability-management", "title": "Vulnerability Management", "layer": "infrastructure",
     "summary": "Identifying and remediating technical vulnerabilities and outdated components.",
     "controls": ["nist-800-53-r5:ra-5", "hitrust-csf:10", "soc2-tsc:cc7",
                  "owasp-web-top10:a06-2021"]},
    {"id": "input-validation", "title": "Input Validation & Injection Defense", "layer": "input",
     "summary": "Validating inputs to prevent injection and malformed-data attacks.",
     "controls": ["nist-800-53-r5:si-10", "owasp-web-top10:a03-2021", "owasp-llm-top10:llm01-2025",
                  "mitre-atlas:aml-t0051", "nist-ai-600-1:ga-2-9"]},
    {"id": "governance-policy", "title": "Governance, Policy & Accountability", "layer": "governance",
     "summary": "Establishing policy, roles, and accountability for security and AI programs.",
     "controls": ["nist-800-53-r5:pm-1", "soc2-tsc:cc1", "hitrust-csf:04", "hitrust-csf:05",
                  "iso-42001:a2", "iso-42001:a3", "nist-ai-rmf:govern-1-1"]},
    {"id": "third-party-risk", "title": "Third-Party & Supply Chain Risk", "layer": "governance",
     "summary": "Managing risks from vendors, partners, and supply-chain components.",
     "controls": ["nist-800-53-r5:sr-3", "soc2-tsc:cc9", "hitrust-csf:05",
                  "iso-42001:a10", "owasp-llm-top10:llm03-2025"]},
    # --- AI-specific domains (one group among the rest) ---
    {"id": "ai-prompt-injection", "title": "AI: Prompt Injection", "layer": "input",
     "summary": "Crafted input overrides an AI model's instructions, directly or via poisoned content.",
     "controls": ["owasp-llm-top10:llm01-2025", "mitre-atlas:aml-t0051", "nist-ai-600-1:ga-2-9",
                  "nist-ai-rmf:measure-2-7", "nist-800-53-r5:si-10"]},
    {"id": "ai-excessive-agency", "title": "AI: Excessive Agency", "layer": "agentic",
     "summary": "An AI agent with too much autonomy or permission takes damaging actions when manipulated.",
     "controls": ["owasp-llm-top10:llm06-2025", "nist-800-53-r5:ac-6", "eu-ai-act:art-14",
                  "iso-42001:a9"]},
    {"id": "ai-data-poisoning", "title": "AI: Data & Model Poisoning", "layer": "model",
     "summary": "Tampered training, fine-tuning, or RAG data corrupts AI model behavior.",
     "controls": ["owasp-llm-top10:llm04-2025", "nist-ai-600-1:ga-2-12", "mitre-atlas:aml-t0020",
                  "iso-42001:a7"]},
    {"id": "ai-governance", "title": "AI: Governance & Oversight", "layer": "governance",
     "summary": "Policy, accountability, human oversight, and lifecycle risk management for AI systems.",
     "controls": ["nist-ai-rmf:govern-1-1", "iso-42001:a2", "iso-42001:a5", "eu-ai-act:art-9",
                  "eu-ai-act:art-14"]},
]

# Cross-framework mappings. Each: from -> to with relation, strength, source.
# Stored once; rendered bidirectionally by the apps.
MAPPINGS = [
    ("nist-800-53-r5:ac-3", "hipaa-security-rule:312-a-1", "equivalent", "strong", "nist-hipaa-crosswalk",
     "Both require enforcing access to ePHI/resources to authorized identities."),
    ("nist-800-53-r5:ac-2", "hipaa-security-rule:308-a-4", "related", "partial", "kyora-iq",
     "Account management overlaps with HIPAA information access management."),
    ("nist-800-53-r5:au-2", "hipaa-security-rule:312-b", "equivalent", "strong", "nist-hipaa-crosswalk",
     "Event logging corresponds to HIPAA audit controls."),
    ("nist-800-53-r5:au-2", "owasp-web-top10:a09-2021", "related", "partial", "kyora-iq",
     "Logging control addresses the web logging/monitoring failure category."),
    ("nist-800-53-r5:si-10", "owasp-llm-top10:llm01-2025", "related", "partial", "kyora-iq",
     "Input validation is a structural defense against prompt injection."),
    ("nist-800-53-r5:si-10", "owasp-web-top10:a03-2021", "related", "strong", "kyora-iq",
     "Input validation directly mitigates injection."),
    ("nist-800-53-r5:ac-6", "owasp-llm-top10:llm06-2025", "related", "strong", "kyora-iq",
     "Least privilege constrains excessive agency."),
    ("owasp-llm-top10:llm01-2025", "nist-ai-600-1:ga-2-9", "related", "strong", "kyora-iq",
     "Prompt injection is an information-security risk in the GenAI profile."),
    ("owasp-llm-top10:llm02-2025", "nist-ai-600-1:ga-2-7", "related", "strong", "kyora-iq",
     "Sensitive disclosure maps to the data-privacy risk."),
    ("owasp-web-top10:a01-2021", "owasp-api-top10:api1-2023", "related", "strong", "kyora-iq",
     "Broken access control manifests as broken object-level authorization in APIs."),
    ("nist-ai-rmf:measure-2-7", "owasp-llm-top10:llm01-2025", "related", "partial", "kyora-iq",
     "Security/resilience measurement covers adversarial input like prompt injection."),
    ("hipaa-security-rule:312-a-1", "owasp-web-top10:a01-2021", "related", "partial", "kyora-iq",
     "HIPAA access control aligns with the broken-access-control risk."),
    # --- wave 2: MITRE ATLAS / ATT&CK ---
    ("owasp-llm-top10:llm01-2025", "mitre-atlas:aml-t0051", "equivalent", "strong", "kyora-iq",
     "OWASP prompt injection corresponds to ATLAS LLM Prompt Injection (AML.T0051)."),
    ("nist-ai-600-1:ga-2-9", "mitre-atlas:aml-t0051", "related", "strong", "kyora-iq",
     "GenAI information-security risk includes the ATLAS prompt-injection technique."),
    ("owasp-llm-top10:llm04-2025", "mitre-atlas:aml-t0020", "equivalent", "strong", "kyora-iq",
     "Data and model poisoning corresponds to ATLAS Poison Training Data (AML.T0020)."),
    ("nist-800-53-r5:ac-3", "mitre-attack:t1078", "related", "partial", "kyora-iq",
     "Access enforcement defends against abuse of valid accounts (T1078)."),
    ("nist-800-53-r5:au-2", "mitre-attack:t1070", "related", "strong", "kyora-iq",
     "Event logging counters indicator removal / log tampering (T1070)."),
    ("owasp-web-top10:a01-2021", "mitre-attack:t1190", "related", "partial", "kyora-iq",
     "Broken access control relates to exploitation of public-facing applications (T1190)."),
    ("owasp-llm-top10:llm10-2025", "mitre-attack:t1499", "related", "partial", "kyora-iq",
     "Unbounded consumption relates to endpoint denial of service (T1499)."),
    # --- wave 3: SOC 2 / ISO 42001 / HITRUST / EU AI Act ---
    ("nist-800-53-r5:ac-3", "soc2-tsc:cc6", "equivalent", "strong", "kyora-iq",
     "Access enforcement aligns with SOC 2 logical and physical access controls (CC6)."),
    ("soc2-tsc:cc6", "hipaa-security-rule:312-a-1", "related", "strong", "kyora-iq",
     "SOC 2 access controls align with the HIPAA access-control standard."),
    ("soc2-tsc:cc7", "nist-800-53-r5:au-2", "related", "strong", "kyora-iq",
     "SOC 2 system operations / monitoring aligns with NIST event logging."),
    ("soc2-tsc:cc8", "owasp-web-top10:a08-2021", "related", "partial", "kyora-iq",
     "SOC 2 change management relates to software and data integrity failures."),
    ("soc2-tsc:cc6", "hitrust-csf:01", "equivalent", "strong", "kyora-iq",
     "SOC 2 access controls correspond to HITRUST access control (01)."),
    ("nist-800-53-r5:au-2", "hitrust-csf:09", "equivalent", "strong", "kyora-iq",
     "Event logging corresponds to HITRUST audit logging and monitoring (09)."),
    ("nist-ai-rmf:govern-1-1", "iso-42001:a2", "related", "strong", "kyora-iq",
     "AI RMF governance aligns with ISO 42001 AI policy."),
    ("nist-ai-rmf:govern-2-1", "iso-42001:a3", "related", "strong", "kyora-iq",
     "AI RMF roles and responsibilities align with ISO 42001 internal organization."),
    ("iso-42001:a5", "eu-ai-act:art-9", "related", "strong", "kyora-iq",
     "ISO 42001 impact assessment aligns with EU AI Act risk management (Art. 9)."),
    ("owasp-llm-top10:llm06-2025", "eu-ai-act:art-14", "related", "strong", "kyora-iq",
     "Excessive agency is mitigated by the EU AI Act human-oversight requirement (Art. 14)."),
    ("nist-800-53-r5:au-2", "eu-ai-act:art-12", "related", "strong", "kyora-iq",
     "Event logging aligns with the EU AI Act record-keeping requirement (Art. 12)."),
    ("nist-ai-600-1:ga-2-7", "eu-ai-act:art-10", "related", "partial", "kyora-iq",
     "Data privacy risk aligns with EU AI Act data governance (Art. 10)."),
]

def load_framework(p: Path):
    return json.loads(p.read_text())

def resolve_index(normdir: Path):
    """Map '<fw>:<control>' -> (title, layer) by scanning all framework files."""
    idx = {}
    fw_meta = []
    for f in sorted(normdir.glob("*.json")):
        if f.name.startswith("_"):
            continue
        data = load_framework(f)
        fw = data["framework"]
        total = 0
        control_count = 0
        # Each framework has a natural "headline control" level; count nodes at
        # that level so the displayed number matches official descriptions.
        #   NIST: base controls + enhancements (not lettered parts)
        #   HIPAA: standards (not implementation specs)
        #   SOC 2 / HITRUST: the nested 'criterion' nodes (criteria / objectives)
        #   others: top-level controls (+ MITRE techniques)
        COUNT_KINDS = {
            "nist-800-53-r5": {"control", "enhancement"},
            "hipaa-security-rule": {"standard"},
            "soc2-tsc": {"criterion"},
            "hitrust-csf": {"criterion"},
            "iso-42001": {"control"},
            "eu-ai-act": {"control"},
        }
        count_kinds = COUNT_KINDS.get(fw["id"])
        def walk(nodes, depth=0):
            nonlocal total, control_count
            for n in nodes:
                total += 1
                if count_kinds is not None:
                    if n.get("kind") in count_kinds:
                        control_count += 1
                else:
                    if depth == 0 or n.get("kind") in {"technique", "subtechnique", "enhancement"}:
                        control_count += 1
                idx[f"{fw['id']}:{n['id']}"] = {"title": n["title"] or n["display_id"], "layer": n.get("layer"), "display_id": n["display_id"]}
                walk(n.get("children", []), depth + 1)
        walk(data["controls"])
        fw_meta.append({"id": fw["id"], "name": fw["name"], "version": fw["version"],
                        "publisher": fw["publisher"], "source_handling": fw["source_handling"],
                        "license": fw["license"], "controls": control_count, "total_nodes": total})
    return idx, fw_meta

ALL_DISCLAIMERS = {
    "soc2-tsc": "The Trust Services Criteria and COSO Principles are proprietary to the AICPA. This tool provides independently-written summaries for educational reference only and is not affiliated with or endorsed by the AICPA. For official criteria text, audit guidance, and SOC 2 reports, visit the AICPA website. Do not rely on this tool for compliance decisions.",
    "iso-42001": "ISO/IEC 42001 is copyrighted by ISO/IEC. This tool provides independently-written summaries of the control structure for educational reference only and is not affiliated with or endorsed by ISO/IEC. Purchase the official standard from ISO for authoritative control text. Do not rely on this tool for compliance decisions.",
    "hitrust-csf": "The HITRUST CSF is proprietary to HITRUST. This tool provides independently-written summaries of the control structure for educational reference only and is not affiliated with or endorsed by HITRUST. Access the official CSF via HITRUST MyCSF for authoritative control text. Do not rely on this tool for compliance decisions.",
    "eu-ai-act": "Summaries of EU AI Act articles are independently written for educational reference. The official, legally binding text is published in the Official Journal of the European Union (Regulation (EU) 2024/1689). Do not rely on this tool for legal or compliance decisions.",
    "hipaa-security-rule": "HIPAA Security Rule text is U.S. public law (45 CFR Part 164). This tool reproduces and summarizes it for educational reference only and is not affiliated with or endorsed by HHS. For authoritative requirements and official guidance, consult the eCFR and HHS. Do not rely on this tool for compliance decisions.",
    "nist-800-53-r5": "NIST SP 800-53 is public domain. Shown for reference — verify against the official NIST publication; do not rely on this tool for compliance decisions.",
    "nist-ai-rmf": "NIST AI RMF is public domain. Shown for reference — verify against the official NIST publication.",
    "nist-ai-600-1": "NIST AI 600-1 is public domain. Shown for reference — verify against the official NIST publication.",
    "owasp-llm-top10": "OWASP content (CC BY-SA 4.0), summarized with attribution. Not endorsed by OWASP. See the official OWASP project for authoritative text.",
    "owasp-api-top10": "OWASP content (CC BY-SA 4.0), summarized with attribution. Not endorsed by OWASP. See the official OWASP project for authoritative text.",
    "owasp-web-top10": "OWASP content (CC BY-SA 4.0), summarized with attribution. Not endorsed by OWASP. See the official OWASP project for authoritative text.",
    "mitre-atlas": "MITRE ATLAS © The MITRE Corporation, summarized with attribution. Not endorsed by MITRE. See the official ATLAS site for authoritative text.",
    "mitre-attack": "MITRE ATT&CK © The MITRE Corporation, curated subset summarized with attribution. Not endorsed by MITRE. See the official ATT&CK site for authoritative text.",
}

def inject_disclaimers(normdir: Path):
    for f in normdir.glob("*.json"):
        if f.name.startswith("_"):
            continue
        d = json.loads(f.read_text())
        fid = d["framework"]["id"]
        if fid in ALL_DISCLAIMERS:
            d["framework"]["disclaimer"] = ALL_DISCLAIMERS[fid]
            f.write_text(json.dumps(d, indent=2, ensure_ascii=False))

def main(normdir_str: str):
    normdir = Path(normdir_str)
    inject_disclaimers(normdir)
    idx, fw_meta = resolve_index(normdir)

    # Validate refs
    problems = []
    for r in RISKS:
        for c in r["controls"]:
            if c not in idx:
                problems.append(f"risk {r['id']} -> missing control {c}")
    built_maps = []
    for frm, to, rel, strength, src, rationale in MAPPINGS:
        if frm not in idx: problems.append(f"mapping from missing {frm}")
        if to not in idx: problems.append(f"mapping to missing {to}")
        if frm in idx and to in idx:
            built_maps.append({
                "from": frm, "from_title": idx[frm]["title"], "from_display": idx[frm]["display_id"],
                "to": to, "to_title": idx[to]["title"], "to_display": idx[to]["display_id"],
                "relation": rel, "strength": strength, "source": src, "rationale": rationale,
            })

    (normdir / "_layers.json").write_text(json.dumps({"layers": LAYERS}, indent=2))
    (normdir / "_risks.json").write_text(json.dumps({
        "risks": [{**r, "controls_resolved": [{"ref": c, **idx[c]} for c in r["controls"] if c in idx]} for r in RISKS]
    }, indent=2, ensure_ascii=False))
    (normdir / "_mappings.json").write_text(json.dumps({"mappings": built_maps}, indent=2, ensure_ascii=False))
    (normdir / "_index.json").write_text(json.dumps({
        "generated_at": datetime.date.today().isoformat(),
        "frameworks": fw_meta,
        "counts": {"frameworks": len(fw_meta), "risks": len(RISKS), "mappings": len(built_maps),
                   "total_control_nodes": sum(m["total_nodes"] for m in fw_meta),
                   "total_controls": sum(m["controls"] for m in fw_meta)},
    }, indent=2))

    print("frameworks:", len(fw_meta))
    print("risks:", len(RISKS), "| mappings:", len(built_maps))
    print("total control nodes:", sum(m['total_nodes'] for m in fw_meta))
    if problems:
        print("PROBLEMS:")
        for p in problems: print("  -", p)
    else:
        print("all risk/mapping refs resolve cleanly")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/normalized")
