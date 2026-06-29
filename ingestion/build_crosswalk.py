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
                  "soc2-tsc:cc6", "owasp-web-top10:a01-2021",
                  "owasp-api-top10:api1-2023", "mitre-attack:t1078"]},
    {"id": "identity-authentication", "title": "Identity & Authentication", "layer": "infrastructure",
     "summary": "Verifying the identity of users and services before granting access.",
     "controls": ["nist-800-53-r5:ia-2", "hipaa-security-rule:312-d", "soc2-tsc:cc6",
                  "owasp-web-top10:a07-2021", "owasp-api-top10:api2-2023",
                  "mitre-attack:t1556"]},
    {"id": "audit-logging", "title": "Audit Logging & Monitoring", "layer": "infrastructure",
     "summary": "Recording and reviewing security-relevant events to detect and investigate activity.",
     "controls": ["nist-800-53-r5:au-2", "hipaa-security-rule:312-b", "soc2-tsc:cc7",
                  "owasp-web-top10:a09-2021", "eu-ai-act:art-12",
                  "mitre-attack:t1070"]},
    {"id": "encryption", "title": "Encryption & Data Protection", "layer": "infrastructure",
     "summary": "Protecting data in transit and at rest with cryptographic controls.",
     "controls": ["nist-800-53-r5:sc-8", "hipaa-security-rule:312-e-1", "soc2-tsc:cc6",
                  "owasp-web-top10:a02-2021"]},
    {"id": "risk-assessment", "title": "Risk Assessment & Management", "layer": "governance",
     "summary": "Identifying, analyzing, and treating risks to systems, data, and objectives.",
     "controls": ["nist-800-53-r5:ra-3", "hipaa-security-rule:308-a-1", "soc2-tsc:cc3",
                  "iso-42001:a5", "nist-ai-rmf:map-1", "eu-ai-act:art-9"]},
    {"id": "incident-response", "title": "Incident Response", "layer": "governance",
     "summary": "Detecting, responding to, and recovering from security incidents.",
     "controls": ["nist-800-53-r5:ir-4", "hipaa-security-rule:308-a-6", "soc2-tsc:cc7"]},
    {"id": "change-management", "title": "Change & Configuration Management", "layer": "infrastructure",
     "summary": "Controlling changes to systems, software, and configurations.",
     "controls": ["nist-800-53-r5:cm-3", "soc2-tsc:cc8", "owasp-web-top10:a08-2021"]},
    {"id": "asset-management", "title": "Asset & Data Classification", "layer": "governance",
     "summary": "Inventorying assets and classifying data by sensitivity.",
     "controls": ["nist-800-53-r5:cm-8", "soc2-tsc:cc6"]},
    {"id": "vulnerability-management", "title": "Vulnerability Management", "layer": "infrastructure",
     "summary": "Identifying and remediating technical vulnerabilities and outdated components.",
     "controls": ["nist-800-53-r5:ra-5", "soc2-tsc:cc7",
                  "owasp-web-top10:a06-2021"]},
    {"id": "input-validation", "title": "Input Validation & Injection Defense", "layer": "input",
     "summary": "Validating inputs to prevent injection and malformed-data attacks.",
     "controls": ["nist-800-53-r5:si-10", "owasp-web-top10:a03-2021", "owasp-llm-top10:llm01-2025",
                  "mitre-atlas:aml-t0051", "nist-ai-600-1:ga-2-9"]},
    {"id": "governance-policy", "title": "Governance, Policy & Accountability", "layer": "governance",
     "summary": "Establishing policy, roles, and accountability for security and AI programs.",
     "controls": ["nist-800-53-r5:pm-1", "soc2-tsc:cc1", "iso-42001:a2", "iso-42001:a3", "nist-ai-rmf:govern-1"]},
    {"id": "third-party-risk", "title": "Third-Party & Supply Chain Risk", "layer": "governance",
     "summary": "Managing risks from vendors, partners, and supply-chain components.",
     "controls": ["nist-800-53-r5:sr-3", "soc2-tsc:cc9", "iso-42001:a10", "owasp-llm-top10:llm03-2025"]},
    {"id": "data-privacy", "title": "Data Privacy & Personal Data Protection", "layer": "governance",
     "summary": "Managing privacy risk to individuals across the data lifecycle: inventory and mapping, consent and notice, data minimization, access, and protection of personal data.",
     "controls": ["nist-privacy-1-0:id-im-p", "nist-privacy-1-0:ct-dm-p", "nist-privacy-1-0:pr-ds-p",
                   "nist-privacy-1-0:pr-ac-p", "nist-800-53-r5:pt-1", "soc2-tsc:p1",
                   "hipaa-security-rule:312-a-1", "nist-ai-600-1:ga-2-7", "eu-ai-act:art-10"]},
    # --- AI security domains (Kyora IQ / Nemesis crosswalk, 16 risks across 5 layers) ---
    {"id": "ai-prompt-injection", "title": "AI: Prompt Injection", "layer": "input",
     "summary": "Crafted input overrides the model's instructions, either directly or through poisoned content it reads from RAG, files, or the web.",
     "controls": ["owasp-llm-top10:llm01-2025", "mitre-atlas:aml-t0051", "mitre-attack:execution", "owasp-api-top10:api8-2023", "owasp-web-top10:a03-2021", "nist-ai-rmf:measure-2", "nist-ai-rmf:manage-2", "iso-42001:a6", "iso-42001:a8", "eu-ai-act:art-15", "nist-800-53-r5:si-10", "nist-800-53-r5:ac-3", "nist-800-53-r5:cm-6", "soc2-tsc:cc6-1", "soc2-tsc:cc6-6", "hipaa-security-rule:312-a-1", "hipaa-security-rule:312-b", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-vector-embedding-weaknesses", "title": "AI: Vector & Embedding Weaknesses", "layer": "input",
     "summary": "RAG retrieval and embedding stores get manipulated or leak data, through poisoned documents, embedding inversion, or cross-tenant retrieval.",
     "controls": ["owasp-llm-top10:llm08-2025", "mitre-atlas:aml-t0020", "mitre-atlas:aml-t0024", "owasp-api-top10:api3-2023", "owasp-web-top10:a01-2021", "nist-ai-rmf:measure-2", "nist-ai-rmf:manage-2", "iso-42001:a6", "eu-ai-act:art-10", "nist-800-53-r5:si-10", "nist-800-53-r5:sa-11", "nist-800-53-r5:sc-28", "soc2-tsc:cc6-1", "soc2-tsc:cc7-1", "hipaa-security-rule:312-b", "nist-ai-600-1:ga-2-9", "nist-ai-600-1:ga-2-7"]},
    {"id": "ai-sensitive-information-disclosure", "title": "AI: Sensitive Information Disclosure", "layer": "output",
     "summary": "The model reveals secrets, PII, or proprietary data in its responses, whether from training data, system context, or other users' data.",
     "controls": ["owasp-llm-top10:llm02-2025", "mitre-atlas:aml-t0057", "mitre-atlas:aml-t0024", "mitre-attack:t1530", "owasp-api-top10:api3-2023", "owasp-web-top10:a02-2021", "nist-ai-rmf:measure-2", "nist-ai-rmf:govern-1", "iso-42001:a6", "iso-42001:a8", "eu-ai-act:art-10", "nist-800-53-r5:ac-3", "nist-800-53-r5:sc-28", "nist-800-53-r5:mp-6", "soc2-tsc:cc6-1", "soc2-tsc:cc6-7", "hipaa-security-rule:312-a-1", "hipaa-security-rule:312-e-1", "nist-ai-600-1:ga-2-7", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-improper-output-handling", "title": "AI: Improper Output Handling", "layer": "output",
     "summary": "Model output is consumed by downstream systems without validation, which can lead to XSS, SSRF, or remote code execution.",
     "controls": ["owasp-llm-top10:llm05-2025", "mitre-atlas:aml-t0048", "mitre-attack:execution", "owasp-api-top10:api7-2023", "owasp-web-top10:a03-2021", "nist-ai-rmf:measure-2", "nist-ai-rmf:manage-2", "iso-42001:a6", "eu-ai-act:art-15", "nist-800-53-r5:si-10", "nist-800-53-r5:cm-6", "nist-800-53-r5:sa-11", "soc2-tsc:cc6-1", "soc2-tsc:cc7-1", "hipaa-security-rule:312-a-1", "nist-ai-600-1:ga-2-9", "nist-ai-600-1:ga-2-8"]},
    {"id": "ai-misinformation", "title": "AI: Misinformation", "layer": "output",
     "summary": "The model produces confidently wrong or fabricated output that users over-trust, leading to harmful decisions.",
     "controls": ["owasp-llm-top10:llm09-2025", "mitre-atlas:aml-t0048", "mitre-atlas:aml-t0047", "nist-ai-rmf:measure-2", "nist-ai-rmf:govern-2", "iso-42001:a6", "iso-42001:a8", "eu-ai-act:art-13", "nist-800-53-r5:si-10", "nist-800-53-r5:sa-11", "soc2-tsc:cc7-1", "soc2-tsc:cc9-1", "hipaa-security-rule:308-a-1", "nist-ai-600-1:ga-2-8"]},
    {"id": "ai-data-model-poisoning", "title": "AI: Data & Model Poisoning", "layer": "model",
     "summary": "Training, fine-tuning, or embedding data is tampered with to implant backdoors, bias, or degraded behavior.",
     "controls": ["owasp-llm-top10:llm04-2025", "mitre-atlas:aml-t0020", "owasp-web-top10:a08-2021", "nist-ai-rmf:measure-2", "nist-ai-rmf:map-2", "iso-42001:a6", "iso-42001:a7", "eu-ai-act:art-10", "nist-800-53-r5:si-10", "nist-800-53-r5:sa-11", "nist-800-53-r5:cm-6", "soc2-tsc:cc7-1", "soc2-tsc:cc9-1", "hipaa-security-rule:312-b", "nist-ai-600-1:ga-2-9", "nist-ai-600-1:ga-2-12"]},
    {"id": "ai-system-prompt-leakage", "title": "AI: System Prompt Leakage", "layer": "model",
     "summary": "The system prompt, which holds rules, secrets, or architecture details, gets extracted through crafted questions.",
     "controls": ["owasp-llm-top10:llm07-2025", "mitre-atlas:aml-t0051", "mitre-atlas:aml-t0057", "mitre-attack:credential-access", "owasp-api-top10:api3-2023", "owasp-web-top10:a05-2021", "nist-ai-rmf:measure-2", "nist-ai-rmf:govern-1", "iso-42001:a6", "eu-ai-act:art-13", "nist-800-53-r5:ac-3", "nist-800-53-r5:sc-28", "nist-800-53-r5:si-10", "soc2-tsc:cc6-1", "soc2-tsc:cc6-7", "hipaa-security-rule:312-a-1", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-model-theft-extraction", "title": "AI: Model Theft & Extraction", "layer": "model",
     "summary": "Unauthorized access to or replication of a proprietary model through query-based extraction or direct exfiltration.",
     "controls": ["mitre-atlas:aml-t0007", "mitre-atlas:aml-t0014", "mitre-attack:t1530", "owasp-api-top10:api2-2023", "owasp-web-top10:a01-2021", "nist-ai-rmf:govern-1", "nist-ai-rmf:manage-2", "iso-42001:a6", "eu-ai-act:art-13", "nist-800-53-r5:ac-3", "nist-800-53-r5:sc-28", "nist-800-53-r5:si-10", "soc2-tsc:cc6-1", "soc2-tsc:cc6-7", "hipaa-security-rule:312-a-1", "nist-ai-600-1:ga-2-9", "nist-ai-600-1:ga-2-12"]},
    {"id": "ai-unbounded-consumption", "title": "AI: Unbounded Consumption", "layer": "infrastructure",
     "summary": "Uncontrolled token, compute, or API consumption, including token floods, recursive expansion, runaway cost, and denial of wallet.",
     "controls": ["owasp-llm-top10:llm10-2025", "mitre-atlas:aml-t0034", "mitre-attack:t1499", "owasp-api-top10:api4-2023", "owasp-web-top10:a05-2021", "nist-ai-rmf:measure-2", "nist-ai-rmf:manage-4", "iso-42001:a6", "eu-ai-act:art-15", "nist-800-53-r5:sc-5", "nist-800-53-r5:si-10", "nist-800-53-r5:ac-3", "soc2-tsc:cc6-6", "soc2-tsc:cc6-1", "hipaa-security-rule:312-a-1", "hipaa-security-rule:312-e-1", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-supply-chain", "title": "AI: Supply Chain", "layer": "infrastructure",
     "summary": "Compromised models, datasets, libraries, or plugins introduce vulnerabilities into the AI pipeline.",
     "controls": ["owasp-llm-top10:llm03-2025", "mitre-atlas:aml-t0010", "mitre-attack:initial-access", "owasp-api-top10:api9-2023", "owasp-web-top10:a06-2021", "nist-ai-rmf:govern-1", "nist-ai-rmf:map-2", "iso-42001:a6", "iso-42001:a7", "eu-ai-act:art-15", "nist-800-53-r5:sa-12", "nist-800-53-r5:sa-11", "nist-800-53-r5:cm-6", "soc2-tsc:cc9-2", "soc2-tsc:cc6-1", "hipaa-security-rule:308-b-1", "nist-ai-600-1:ga-2-12"]},
    {"id": "ai-api-authentication-access", "title": "AI: API Authentication & Access", "layer": "infrastructure",
     "summary": "The endpoint serving the model lacks auth, leaks keys, or allows unauthenticated access, which is the classic API attack surface.",
     "controls": ["mitre-atlas:aml-t0012", "mitre-attack:t1190", "owasp-api-top10:api2-2023", "owasp-api-top10:api1-2023", "owasp-web-top10:a01-2021", "owasp-web-top10:a07-2021", "nist-ai-rmf:measure-2", "iso-42001:a6", "eu-ai-act:art-15", "nist-800-53-r5:ia-3", "nist-800-53-r5:ac-3", "nist-800-53-r5:sc-28", "soc2-tsc:cc6-1", "soc2-tsc:cc6-3", "hipaa-security-rule:312-a-1", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-security-misconfiguration", "title": "AI: Security Misconfiguration", "layer": "infrastructure",
     "summary": "Missing security headers, wildcard CORS, verbose errors, exposed files, or no HTTPS enforcement on the AI service.",
     "controls": ["mitre-attack:t1190", "owasp-api-top10:api7-2023", "owasp-api-top10:api8-2023", "owasp-web-top10:a05-2021", "nist-ai-rmf:manage-4", "iso-42001:a6", "eu-ai-act:art-15", "nist-800-53-r5:cm-6", "nist-800-53-r5:sc-7", "nist-800-53-r5:au-2", "soc2-tsc:cc6-1", "soc2-tsc:cc6-6", "hipaa-security-rule:312-a-1", "hipaa-security-rule:308-a-1", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-excessive-agency", "title": "AI: Excessive Agency", "layer": "agentic",
     "summary": "An agent has too much autonomy, permission, or tool access, letting manipulation translate into real-world actions.",
     "controls": ["owasp-llm-top10:llm06-2025", "mitre-atlas:aml-t0053", "mitre-atlas:aml-t0054", "mitre-attack:execution", "mitre-attack:t1078", "owasp-api-top10:api5-2023", "owasp-web-top10:a01-2021", "nist-ai-rmf:govern-1", "nist-ai-rmf:manage-4", "iso-42001:a6", "eu-ai-act:art-14", "nist-800-53-r5:ac-3", "nist-800-53-r5:ac-6", "nist-800-53-r5:cm-7", "soc2-tsc:cc6-1", "soc2-tsc:cc6-3", "hipaa-security-rule:312-a-1", "hipaa-security-rule:308-a-3", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-agentic-tool-chain-abuse", "title": "AI: Agentic Tool & Chain Abuse", "layer": "agentic",
     "summary": "Multi-step agents get hijacked through tool outputs, memory poisoning, or chained calls that compound a single injection.",
     "controls": ["owasp-llm-top10:llm06-2025", "owasp-llm-top10:llm01-2025", "mitre-atlas:aml-t0086", "mitre-atlas:aml-t0110", "mitre-attack:execution", "owasp-api-top10:api5-2023", "owasp-api-top10:api8-2023", "owasp-web-top10:a04-2021", "nist-ai-rmf:govern-1", "nist-ai-rmf:manage-2", "iso-42001:a6", "iso-42001:a7", "eu-ai-act:art-14", "nist-800-53-r5:ac-3", "nist-800-53-r5:ac-6", "nist-800-53-r5:cm-7", "nist-800-53-r5:sa-11", "soc2-tsc:cc6-1", "soc2-tsc:cc6-3", "hipaa-security-rule:312-a-1", "hipaa-security-rule:308-a-1", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-insufficient-human-oversight", "title": "AI: Insufficient Human Oversight", "layer": "agentic",
     "summary": "No human in the loop or audit trail on high-impact agent actions, so failures and manipulations go unchecked.",
     "controls": ["owasp-llm-top10:llm06-2025", "mitre-atlas:aml-t0086", "owasp-web-top10:a04-2021", "nist-ai-rmf:govern-1", "nist-ai-rmf:measure-2", "iso-42001:a6", "iso-42001:a8", "eu-ai-act:art-14", "nist-800-53-r5:ac-3", "nist-800-53-r5:au-2", "nist-800-53-r5:cm-6", "soc2-tsc:cc6-1", "soc2-tsc:cc7-2", "hipaa-security-rule:312-a-1", "hipaa-security-rule:312-b", "nist-ai-600-1:ga-2-9"]},
    {"id": "ai-mcp-connector-tool-abuse", "title": "AI: MCP & Connector Tool Abuse", "layer": "agentic",
     "summary": "Untrusted or over-permissioned tool servers (for example MCP servers and third-party connectors) feed poisoned tool output, hijack tool calls, or hand an agent capabilities it should not have. Documented in real autonomous-attack tradecraft where penetration tools were wired in as MCP servers to turn an agent into an attack platform.",
     "controls": ["owasp-llm-top10:llm06-2025", "owasp-llm-top10:llm03-2025", "mitre-atlas:aml-t0110", "mitre-atlas:aml-t0053", "mitre-atlas:aml-t0086", "mitre-attack:execution", "mitre-attack:t1078", "owasp-api-top10:api5-2023", "owasp-api-top10:api8-2023", "owasp-web-top10:a04-2021", "owasp-web-top10:a01-2021", "nist-ai-rmf:govern-1", "nist-ai-rmf:manage-2", "iso-42001:a6", "iso-42001:a7", "eu-ai-act:art-14", "nist-800-53-r5:ac-6", "nist-800-53-r5:cm-7", "nist-800-53-r5:sa-9", "soc2-tsc:cc6-1", "soc2-tsc:cc6-3", "hipaa-security-rule:312-a-1", "hipaa-security-rule:308-b-1", "nist-ai-600-1:ga-2-12", "nist-ai-600-1:ga-2-9"]},
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
    ("nist-ai-rmf:measure-2", "owasp-llm-top10:llm01-2025", "related", "partial", "kyora-iq",
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
    # --- wave 3: SOC 2 / ISO 42001 / EU AI Act ---
    ("nist-800-53-r5:ac-3", "soc2-tsc:cc6", "equivalent", "strong", "kyora-iq",
     "Access enforcement aligns with SOC 2 logical and physical access controls (CC6)."),
    ("soc2-tsc:cc6", "hipaa-security-rule:312-a-1", "related", "strong", "kyora-iq",
     "SOC 2 access controls align with the HIPAA access-control standard."),
    ("soc2-tsc:cc7", "nist-800-53-r5:au-2", "related", "strong", "kyora-iq",
     "SOC 2 system operations / monitoring aligns with NIST event logging."),
    ("soc2-tsc:cc8", "owasp-web-top10:a08-2021", "related", "partial", "kyora-iq",
     "SOC 2 change management relates to software and data integrity failures."),
    ("nist-ai-rmf:govern-1", "iso-42001:a2", "related", "strong", "kyora-iq",
     "AI RMF governance aligns with ISO 42001 AI policy."),
    ("nist-ai-rmf:govern-2", "iso-42001:a3", "related", "strong", "kyora-iq",
     "AI RMF roles and responsibilities align with ISO 42001 internal organization."),
    ("iso-42001:a5", "eu-ai-act:art-9", "related", "strong", "kyora-iq",
     "ISO 42001 impact assessment aligns with EU AI Act risk management (Art. 9)."),
    ("owasp-llm-top10:llm06-2025", "eu-ai-act:art-14", "related", "strong", "kyora-iq",
     "Excessive agency is mitigated by the EU AI Act human-oversight requirement (Art. 14)."),
    ("nist-800-53-r5:au-2", "eu-ai-act:art-12", "related", "strong", "kyora-iq",
     "Event logging aligns with the EU AI Act record-keeping requirement (Art. 12)."),
    ("nist-ai-600-1:ga-2-7", "eu-ai-act:art-10", "related", "partial", "kyora-iq",
     "Data privacy risk aligns with EU AI Act data governance (Art. 10)."),

    # ===================================================================
    # Hand-authored crosswalk (Kyora IQ interpretation). Each links a NIST
    # 800-53 control to the equivalent in another framework. Reasoned from
    # the controls' purpose; clearly tagged kyora-iq, not an official mapping.
    # ===================================================================

    # --- Access control family (AC) -> SOC2 / HIPAA ---
    ("nist-800-53-r5:ac-2", "soc2-tsc:cc6-2", "related", "strong", "kyora-iq",
     "Account management aligns with SOC 2 CC6.2 (register and authorize new users)."),
    ("nist-800-53-r5:ac-2", "soc2-tsc:cc6-3", "related", "strong", "kyora-iq",
     "Account management aligns with SOC 2 CC6.3 (role-based access and least privilege)."),
    ("nist-800-53-r5:ac-2", "hipaa-security-rule:308-a-4", "related", "strong", "kyora-iq",
     "Account management aligns with the HIPAA Information Access Management standard."),
    ("nist-800-53-r5:ac-3", "soc2-tsc:cc6-1", "related", "strong", "kyora-iq",
     "Access enforcement aligns with SOC 2 CC6.1 (logical access security)."),
    ("nist-800-53-r5:ac-5", "soc2-tsc:cc6-3", "related", "strong", "kyora-iq",
     "Separation of duties aligns with SOC 2 CC6.3 (role-based access and segregation of incompatible functions)."),
    ("nist-800-53-r5:ac-6", "soc2-tsc:cc6-3", "related", "strong", "kyora-iq",
     "Least privilege aligns with SOC 2 CC6.3 (access based on least privilege)."),
    ("nist-800-53-r5:ac-6", "hipaa-security-rule:312-a-1", "related", "partial", "kyora-iq",
     "Least privilege supports the HIPAA Access Control standard."),
    ("nist-800-53-r5:ac-7", "hipaa-security-rule:312-a-1", "related", "partial", "kyora-iq",
     "Unsuccessful logon attempts support the HIPAA Access Control standard."),
    ("nist-800-53-r5:ac-17", "soc2-tsc:cc6-6", "related", "strong", "kyora-iq",
     "Remote access aligns with SOC 2 CC6.6 (protection from threats outside the boundary)."),

    # --- Identification & Authentication (IA) ---
    ("nist-800-53-r5:ia-2", "soc2-tsc:cc6-1", "related", "strong", "kyora-iq",
     "User authentication aligns with SOC 2 CC6.1 (logical access security)."),
    ("nist-800-53-r5:ia-2", "hipaa-security-rule:312-d", "related", "strong", "kyora-iq",
     "User authentication aligns with the HIPAA Person or Entity Authentication standard."),
    ("nist-800-53-r5:ia-5", "hipaa-security-rule:312-d", "related", "partial", "kyora-iq",
     "Authenticator management supports HIPAA Person or Entity Authentication."),

    # --- Audit & Accountability (AU) ---
    ("nist-800-53-r5:au-2", "soc2-tsc:cc7-2", "related", "strong", "kyora-iq",
     "Event logging aligns with SOC 2 CC7.2 (monitoring for anomalies)."),
    ("nist-800-53-r5:au-6", "soc2-tsc:cc7-3", "related", "strong", "kyora-iq",
     "Audit review aligns with SOC 2 CC7.3 (evaluating security events)."),
    ("nist-800-53-r5:au-6", "hipaa-security-rule:308-a-1", "related", "partial", "kyora-iq",
     "Audit review supports the HIPAA Information System Activity Review specification."),
    ("nist-800-53-r5:au-2", "hipaa-security-rule:312-b", "related", "strong", "kyora-iq",
     "Event logging aligns with the HIPAA Audit Controls standard."),

    # --- Incident Response (IR) ---
    ("nist-800-53-r5:ir-4", "soc2-tsc:cc7-4", "related", "strong", "kyora-iq",
     "Incident handling aligns with SOC 2 CC7.4 (responding to security incidents)."),
    ("nist-800-53-r5:ir-4", "hipaa-security-rule:308-a-6", "related", "strong", "kyora-iq",
     "Incident handling aligns with the HIPAA Security Incident Procedures standard."),

    # --- Contingency Planning (CP) ---
    ("nist-800-53-r5:cp-9", "hipaa-security-rule:308-a-7", "related", "strong", "kyora-iq",
     "System backup aligns with the HIPAA Contingency Plan standard (data backup)."),
    ("nist-800-53-r5:cp-10", "hipaa-security-rule:308-a-7", "related", "strong", "kyora-iq",
     "System recovery aligns with the HIPAA Contingency Plan standard (disaster recovery)."),

    # --- Risk Assessment (RA) ---
    ("nist-800-53-r5:ra-3", "soc2-tsc:cc3-2", "related", "strong", "kyora-iq",
     "Risk assessment aligns with SOC 2 CC3.2 (identify and analyze risk)."),
    ("nist-800-53-r5:ra-3", "hipaa-security-rule:308-a-1", "related", "strong", "kyora-iq",
     "Risk assessment aligns with the HIPAA Security Management Process (risk analysis)."),
    ("nist-800-53-r5:ra-3", "iso-42001:a5", "related", "partial", "kyora-iq",
     "Risk assessment aligns with ISO 42001 AI system impact assessment."),
    ("nist-800-53-r5:ra-5", "soc2-tsc:cc7-1", "related", "strong", "kyora-iq",
     "Vulnerability monitoring aligns with SOC 2 CC7.1 (detecting vulnerabilities)."),

    # --- Configuration / Change Management (CM) ---
    ("nist-800-53-r5:cm-3", "soc2-tsc:cc8-1", "related", "strong", "kyora-iq",
     "Configuration change control aligns with SOC 2 CC8.1 (change management)."),

    # --- System & Communications Protection (SC) ---
    ("nist-800-53-r5:sc-8", "hipaa-security-rule:312-e-1", "related", "strong", "kyora-iq",
     "Transmission confidentiality aligns with the HIPAA Transmission Security standard."),
    ("nist-800-53-r5:sc-28", "hipaa-security-rule:312-c-1", "related", "partial", "kyora-iq",
     "Protection of information at rest supports the HIPAA Integrity standard."),
    ("nist-800-53-r5:sc-7", "soc2-tsc:cc6-6", "related", "strong", "kyora-iq",
     "Boundary protection aligns with SOC 2 CC6.6 (protecting the system boundary)."),

    # --- System & Information Integrity (SI) ---
    ("nist-800-53-r5:si-4", "soc2-tsc:cc7-2", "related", "strong", "kyora-iq",
     "System monitoring aligns with SOC 2 CC7.2 (monitoring for anomalies)."),
    ("nist-800-53-r5:si-3", "owasp-web-top10:a08-2021", "related", "partial", "kyora-iq",
     "Malicious code protection relates to software and data integrity failures."),

    # --- Governance / Program Management (PM) -> SOC2 / ISO ---
    ("nist-800-53-r5:pm-1", "soc2-tsc:cc1-1", "related", "strong", "kyora-iq",
     "Information security program plan aligns with SOC 2 CC1.1 (control environment)."),
    ("nist-800-53-r5:pm-9", "soc2-tsc:cc3-1", "related", "partial", "kyora-iq",
     "Risk management strategy aligns with SOC 2 CC3.1 (specifying objectives for risk)."),
    ("nist-800-53-r5:pm-1", "iso-42001:a2", "related", "partial", "kyora-iq",
     "Security program plan parallels ISO 42001 AI policy at the governance level."),

    # --- Supply Chain (SR) -> SOC2 / ISO ---
    ("nist-800-53-r5:sr-3", "soc2-tsc:cc9-2", "related", "strong", "kyora-iq",
     "Supply chain controls align with SOC 2 CC9.2 (vendor and business partner risk)."),
    ("nist-800-53-r5:sr-3", "iso-42001:a10", "related", "partial", "kyora-iq",
     "Supply chain controls align with ISO 42001 third-party relationships."),

    # --- Awareness & Training (AT) ---
    ("nist-800-53-r5:at-2", "hipaa-security-rule:308-a-5", "related", "strong", "kyora-iq",
     "Security awareness training aligns with the HIPAA Security Awareness and Training standard."),

    # --- Physical (PE) ---
    ("nist-800-53-r5:pe-3", "hipaa-security-rule:310-a-1", "related", "strong", "kyora-iq",
     "Physical access control aligns with the HIPAA Facility Access Controls standard."),

    # --- AI governance cross-links ---
    ("nist-ai-rmf:govern-1", "soc2-tsc:cc1-1", "related", "partial", "kyora-iq",
     "AI governance parallels SOC 2 CC1.1 control environment at the program level."),
    ("iso-42001:a6", "eu-ai-act:art-15", "related", "partial", "kyora-iq",
     "ISO 42001 AI lifecycle aligns with EU AI Act accuracy and robustness (Art. 15)."),
    ("iso-42001:a8", "eu-ai-act:art-13", "related", "strong", "kyora-iq",
     "ISO 42001 information for interested parties aligns with EU AI Act transparency (Art. 13)."),

    # ===================================================================
    # Expansion set 2 (Kyora IQ interpretation). Targets direct framework-to-
    # framework pairs and fuller OWASP / MITRE / AI coverage.
    # ===================================================================

    # --- HIPAA <-> SOC 2 (direct) ---
    ("hipaa-security-rule:312-a-1", "soc2-tsc:cc6-1", "related", "strong", "kyora-iq",
     "HIPAA Access Control aligns with SOC 2 CC6.1 (logical access security)."),
    ("hipaa-security-rule:312-d", "soc2-tsc:cc6-1", "related", "strong", "kyora-iq",
     "HIPAA Person or Entity Authentication aligns with SOC 2 CC6.1."),
    ("hipaa-security-rule:312-b", "soc2-tsc:cc7-2", "related", "strong", "kyora-iq",
     "HIPAA Audit Controls align with SOC 2 CC7.2 (system monitoring)."),
    ("hipaa-security-rule:308-a-6", "soc2-tsc:cc7-4", "related", "strong", "kyora-iq",
     "HIPAA Security Incident Procedures align with SOC 2 CC7.4 (incident response)."),
    ("hipaa-security-rule:308-a-1", "soc2-tsc:cc3-2", "related", "strong", "kyora-iq",
     "HIPAA Security Management Process (risk analysis) aligns with SOC 2 CC3.2."),
    ("hipaa-security-rule:308-a-5", "soc2-tsc:cc1-4", "related", "partial", "kyora-iq",
     "HIPAA Security Awareness and Training aligns with SOC 2 CC1.4 (competence)."),
    ("hipaa-security-rule:308-a-3", "soc2-tsc:cc6-3", "related", "partial", "kyora-iq",
     "HIPAA Workforce Security aligns with SOC 2 CC6.3 (role-based access)."),
    ("hipaa-security-rule:308-a-7", "soc2-tsc:cc7-5", "related", "strong", "kyora-iq",
     "HIPAA Contingency Plan aligns with SOC 2 CC7.5 (recovery from incidents)."),
    ("hipaa-security-rule:308-b-1", "soc2-tsc:cc9-2", "related", "strong", "kyora-iq",
     "HIPAA Business Associate Contracts align with SOC 2 CC9.2 (vendor risk)."),
    ("hipaa-security-rule:312-e-1", "soc2-tsc:cc6-7", "related", "strong", "kyora-iq",
     "HIPAA Transmission Security aligns with SOC 2 CC6.7 (restricting information in transit)."),



    # --- SOC 2 <-> ISO 42001 (governance) ---
    ("soc2-tsc:cc1-1", "iso-42001:a2", "related", "partial", "kyora-iq",
     "SOC 2 control environment parallels ISO 42001 AI policy at the governance level."),
    ("soc2-tsc:cc1-3", "iso-42001:a3", "related", "partial", "kyora-iq",
     "SOC 2 structures and reporting lines parallel ISO 42001 internal organization."),
    ("soc2-tsc:cc3-2", "iso-42001:a5", "related", "partial", "kyora-iq",
     "SOC 2 risk assessment parallels ISO 42001 AI system impact assessment."),

    # --- NIST AI RMF <-> EU AI Act / ISO 42001 / SOC2 ---
    ("nist-ai-rmf:govern-1", "eu-ai-act:art-9", "related", "strong", "kyora-iq",
     "AI RMF governance of legal requirements aligns with EU AI Act risk management (Art. 9)."),
    ("nist-ai-rmf:govern-2", "iso-42001:a3", "related", "strong", "kyora-iq",
     "AI RMF roles and responsibilities align with ISO 42001 internal organization."),
    ("nist-ai-rmf:map-1", "iso-42001:a5", "related", "strong", "kyora-iq",
     "AI RMF context and intended purpose aligns with ISO 42001 impact assessment."),
    ("nist-ai-rmf:measure-2", "eu-ai-act:art-15", "related", "strong", "kyora-iq",
     "AI RMF security and resilience aligns with EU AI Act robustness and cybersecurity (Art. 15)."),
    ("nist-ai-rmf:measure-2", "eu-ai-act:art-10", "related", "partial", "kyora-iq",
     "AI RMF harmful bias measurement aligns with EU AI Act data governance (Art. 10)."),
    ("nist-ai-rmf:manage-4", "eu-ai-act:art-14", "related", "partial", "kyora-iq",
     "AI RMF post-deployment monitoring supports EU AI Act human oversight (Art. 14)."),
    ("nist-ai-rmf:manage-4", "iso-42001:a6", "related", "strong", "kyora-iq",
     "AI RMF post-deployment monitoring aligns with ISO 42001 AI system lifecycle."),

    # --- NIST AI 600-1 (GenAI) cross-links ---
    ("nist-ai-600-1:ga-2-9", "owasp-llm-top10:llm01-2025", "related", "strong", "kyora-iq",
     "GenAI information security risk includes OWASP prompt injection."),
    ("nist-ai-600-1:ga-2-8", "owasp-llm-top10:llm09-2025", "related", "strong", "kyora-iq",
     "GenAI confabulation aligns with OWASP misinformation (LLM09)."),
    ("nist-ai-600-1:ga-2-7", "owasp-llm-top10:llm02-2025", "related", "strong", "kyora-iq",
     "GenAI data privacy aligns with OWASP sensitive information disclosure (LLM02)."),
    ("nist-ai-600-1:ga-2-12", "owasp-llm-top10:llm03-2025", "related", "strong", "kyora-iq",
     "GenAI value chain integrity aligns with OWASP supply chain (LLM03)."),
    ("nist-ai-600-1:ga-2-7", "eu-ai-act:art-10", "related", "strong", "kyora-iq",
     "GenAI data privacy aligns with EU AI Act data governance (Art. 10)."),
    ("nist-ai-600-1:ga-2-9", "nist-800-53-r5:si-10", "related", "partial", "kyora-iq",
     "GenAI information security relates to NIST input validation (SI-10)."),

    # --- OWASP LLM <-> ATLAS / NIST / EU ---
    ("owasp-llm-top10:llm01-2025", "mitre-atlas:aml-t0051", "equivalent", "strong", "kyora-iq",
     "OWASP prompt injection corresponds to ATLAS LLM Prompt Injection (AML.T0051)."),
    ("owasp-llm-top10:llm04-2025", "mitre-atlas:aml-t0020", "equivalent", "strong", "kyora-iq",
     "OWASP data and model poisoning corresponds to ATLAS Poison Training Data (AML.T0020)."),
    ("owasp-llm-top10:llm03-2025", "mitre-atlas:aml-t0058", "related", "strong", "kyora-iq",
     "OWASP supply chain relates to ATLAS Publish Poisoned Models (AML.T0058)."),
    ("owasp-llm-top10:llm06-2025", "nist-800-53-r5:ac-6", "related", "strong", "kyora-iq",
     "OWASP excessive agency aligns with NIST least privilege (AC-6)."),
    ("owasp-llm-top10:llm06-2025", "eu-ai-act:art-14", "related", "strong", "kyora-iq",
     "OWASP excessive agency is mitigated by EU AI Act human oversight (Art. 14)."),
    ("owasp-llm-top10:llm10-2025", "nist-800-53-r5:sc-5", "related", "partial", "kyora-iq",
     "OWASP unbounded consumption relates to NIST denial-of-service protection (SC-5)."),
    ("owasp-llm-top10:llm05-2025", "nist-800-53-r5:si-10", "related", "partial", "kyora-iq",
     "OWASP improper output handling relates to NIST information input/output validation."),

    # --- OWASP API <-> NIST / OWASP Web ---
    ("owasp-api-top10:api1-2023", "nist-800-53-r5:ac-3", "related", "strong", "kyora-iq",
     "Broken object-level authorization relates to NIST access enforcement (AC-3)."),
    ("owasp-api-top10:api2-2023", "nist-800-53-r5:ia-2", "related", "strong", "kyora-iq",
     "Broken authentication relates to NIST user authentication (IA-2)."),
    ("owasp-api-top10:api5-2023", "nist-800-53-r5:ac-6", "related", "strong", "kyora-iq",
     "Broken function-level authorization relates to NIST least privilege (AC-6)."),
    ("owasp-api-top10:api8-2023", "nist-800-53-r5:cm-6", "related", "strong", "kyora-iq",
     "API security misconfiguration relates to NIST configuration settings (CM-6)."),
    ("owasp-api-top10:api9-2023", "nist-800-53-r5:cm-8", "related", "partial", "kyora-iq",
     "Improper inventory management relates to NIST system component inventory (CM-8)."),
    ("owasp-api-top10:api4-2023", "owasp-llm-top10:llm10-2025", "related", "strong", "kyora-iq",
     "API unrestricted resource consumption parallels OWASP unbounded consumption."),
    ("owasp-api-top10:api1-2023", "owasp-web-top10:a01-2021", "equivalent", "strong", "kyora-iq",
     "API broken object-level authorization parallels web broken access control."),

    # --- OWASP Web <-> NIST ---
    ("owasp-web-top10:a01-2021", "nist-800-53-r5:ac-3", "related", "strong", "kyora-iq",
     "Broken access control relates to NIST access enforcement (AC-3)."),
    ("owasp-web-top10:a02-2021", "nist-800-53-r5:sc-13", "related", "strong", "kyora-iq",
     "Cryptographic failures relate to NIST cryptographic protection (SC-13)."),
    ("owasp-web-top10:a03-2021", "nist-800-53-r5:si-10", "related", "strong", "kyora-iq",
     "Injection relates to NIST information input validation (SI-10)."),
    ("owasp-web-top10:a05-2021", "nist-800-53-r5:cm-6", "related", "strong", "kyora-iq",
     "Security misconfiguration relates to NIST configuration settings (CM-6)."),
    ("owasp-web-top10:a06-2021", "nist-800-53-r5:ra-5", "related", "strong", "kyora-iq",
     "Vulnerable and outdated components relate to NIST vulnerability monitoring (RA-5)."),
    ("owasp-web-top10:a07-2021", "nist-800-53-r5:ia-2", "related", "strong", "kyora-iq",
     "Identification and authentication failures relate to NIST user authentication (IA-2)."),
    ("owasp-web-top10:a09-2021", "nist-800-53-r5:au-2", "related", "strong", "kyora-iq",
     "Security logging and monitoring failures relate to NIST event logging (AU-2)."),
    ("owasp-web-top10:a04-2021", "nist-800-53-r5:sa-8", "related", "partial", "kyora-iq",
     "Insecure design relates to NIST security engineering principles (SA-8)."),
    ("owasp-web-top10:a10-2021", "nist-800-53-r5:sc-7", "related", "partial", "kyora-iq",
     "Server-side request forgery relates to NIST boundary protection (SC-7)."),
    ("owasp-web-top10:a08-2021", "nist-800-53-r5:si-7", "related", "strong", "kyora-iq",
     "Software and data integrity failures relate to NIST software/information integrity (SI-7)."),

    # --- MITRE ATT&CK <-> NIST (defensive control for each technique) ---
    ("mitre-attack:t1190", "nist-800-53-r5:ra-5", "related", "strong", "kyora-iq",
     "Exploit public-facing application is countered by NIST vulnerability monitoring (RA-5)."),
    ("mitre-attack:t1078", "nist-800-53-r5:ac-2", "related", "strong", "kyora-iq",
     "Valid accounts abuse is countered by NIST account management (AC-2)."),
    ("mitre-attack:t1110", "nist-800-53-r5:ac-7", "related", "strong", "kyora-iq",
     "Brute force is countered by NIST unsuccessful logon attempts (AC-7)."),
    ("mitre-attack:t1556", "nist-800-53-r5:ia-2", "related", "strong", "kyora-iq",
     "Modify authentication process is countered by NIST user authentication (IA-2)."),
    ("mitre-attack:t1068", "nist-800-53-r5:ac-6", "related", "strong", "kyora-iq",
     "Privilege escalation is countered by NIST least privilege (AC-6)."),
    ("mitre-attack:t1098", "nist-800-53-r5:ac-2", "related", "strong", "kyora-iq",
     "Account manipulation is countered by NIST account management (AC-2)."),
    ("mitre-attack:t1530", "nist-800-53-r5:sc-28", "related", "strong", "kyora-iq",
     "Data from cloud storage is countered by NIST protection of information at rest (SC-28)."),
    ("mitre-attack:t1048", "nist-800-53-r5:sc-7", "related", "strong", "kyora-iq",
     "Exfiltration over alternative protocol is countered by NIST boundary protection (SC-7)."),
    ("mitre-attack:t1485", "nist-800-53-r5:cp-9", "related", "strong", "kyora-iq",
     "Data destruction is countered by NIST system backup (CP-9)."),
    ("mitre-attack:t1562", "nist-800-53-r5:si-4", "related", "strong", "kyora-iq",
     "Impair defenses is countered by NIST system monitoring (SI-4)."),
    ("mitre-attack:t1070", "nist-800-53-r5:au-9", "related", "strong", "kyora-iq",
     "Indicator removal is countered by NIST protection of audit information (AU-9)."),
    ("mitre-attack:t1046", "nist-800-53-r5:sc-7", "related", "partial", "kyora-iq",
     "Network service discovery is countered by NIST boundary protection (SC-7)."),

    # --- MITRE ATLAS <-> NIST AI / OWASP / NIST ---
    ("mitre-atlas:aml-t0020", "nist-ai-600-1:ga-2-12", "related", "strong", "kyora-iq",
     "ATLAS poison training data aligns with GenAI value chain integrity."),
    ("mitre-atlas:aml-t0051", "nist-ai-rmf:measure-2", "related", "strong", "kyora-iq",
     "ATLAS prompt injection relates to AI RMF security and resilience."),
    ("mitre-atlas:aml-t0058", "owasp-llm-top10:llm03-2025", "related", "strong", "kyora-iq",
     "ATLAS publish poisoned models aligns with OWASP supply chain (LLM03)."),
    ("mitre-atlas:aml-t0019", "owasp-llm-top10:llm04-2025", "related", "strong", "kyora-iq",
     "ATLAS publish poisoned datasets aligns with OWASP data and model poisoning."),
    ("mitre-atlas:aml-t0051", "eu-ai-act:art-15", "related", "partial", "kyora-iq",
     "ATLAS prompt injection relates to EU AI Act robustness and cybersecurity (Art. 15)."),

    # --- ISO 42001 <-> EU AI Act (fuller) ---
    ("iso-42001:a4", "eu-ai-act:art-10", "related", "partial", "kyora-iq",
     "ISO 42001 resources for AI systems support EU AI Act data governance (Art. 10)."),
    ("iso-42001:a6", "eu-ai-act:art-9", "related", "strong", "kyora-iq",
     "ISO 42001 AI lifecycle aligns with EU AI Act risk management (Art. 9)."),
    ("iso-42001:a7", "eu-ai-act:art-10", "related", "strong", "kyora-iq",
     "ISO 42001 data for AI systems aligns with EU AI Act data governance (Art. 10)."),
    ("iso-42001:a9", "eu-ai-act:art-14", "related", "strong", "kyora-iq",
     "ISO 42001 responsible use aligns with EU AI Act human oversight (Art. 14)."),

    # --- NIST 800-53 additional families -> SOC2 ---
    ("nist-800-53-r5:ac-4", "soc2-tsc:cc6-7", "related", "partial", "kyora-iq",
     "Information flow enforcement aligns with SOC 2 CC6.7 (restricting information movement)."),
    ("nist-800-53-r5:au-9", "soc2-tsc:cc7-2", "related", "partial", "kyora-iq",
     "Protection of audit information supports SOC 2 CC7.2 monitoring integrity."),
    ("nist-800-53-r5:cm-6", "soc2-tsc:cc7-1", "related", "strong", "kyora-iq",
     "Configuration settings align with SOC 2 CC7.1 (detecting configuration changes)."),
    ("nist-800-53-r5:mp-6", "hipaa-security-rule:310-d-1", "related", "strong", "kyora-iq",
     "Media sanitization aligns with the HIPAA Device and Media Controls standard."),
    ("nist-800-53-r5:pe-3", "soc2-tsc:cc6-4", "related", "strong", "kyora-iq",
     "Physical access control aligns with SOC 2 CC6.4 (restricting physical access)."),
    ("nist-800-53-r5:ps-3", "hipaa-security-rule:308-a-3", "related", "partial", "kyora-iq",
     "Personnel screening aligns with the HIPAA Workforce Security standard."),
    ("nist-800-53-r5:sa-8", "iso-42001:a6", "related", "partial", "kyora-iq",
     "Security engineering principles align with ISO 42001 AI system lifecycle."),
    ("nist-800-53-r5:si-7", "hipaa-security-rule:312-c-1", "related", "strong", "kyora-iq",
     "Software and information integrity aligns with the HIPAA Integrity standard."),

    # --- SOC 2 internal criteria -> NIST (governance depth) ---
    ("nist-800-53-r5:ca-2", "soc2-tsc:cc4-1", "related", "strong", "kyora-iq",
     "Control assessments align with SOC 2 CC4.1 (ongoing evaluations)."),
    ("nist-800-53-r5:ca-7", "soc2-tsc:cc4-1", "related", "strong", "kyora-iq",
     "Continuous monitoring aligns with SOC 2 CC4.1 (ongoing evaluations)."),
    ("nist-800-53-r5:pl-2", "soc2-tsc:cc5-3", "related", "partial", "kyora-iq",
     "System security plan aligns with SOC 2 CC5.3 (policies and procedures)."),


    # --- AI RMF <-> NIST 800-53 (governance bridge) ---
    ("nist-ai-rmf:govern-1", "nist-800-53-r5:pm-1", "related", "partial", "kyora-iq",
     "AI RMF governance aligns with the NIST security program plan (PM-1)."),
    ("nist-ai-rmf:manage-2", "nist-800-53-r5:ca-7", "related", "partial", "kyora-iq",
     "AI RMF mechanisms to sustain value align with NIST continuous monitoring (CA-7)."),

    # --- NIST Privacy Framework <-> other frameworks ---
    ("nist-privacy-1-0:id-im-p", "nist-800-53-r5:cm-8", "related", "strong", "kyora-iq",
     "Privacy inventory and mapping aligns with NIST system component inventory (CM-8)."),
    ("nist-privacy-1-0:id-ra-p", "nist-800-53-r5:ra-3", "related", "strong", "kyora-iq",
     "Privacy risk assessment aligns with NIST risk assessment (RA-3)."),
    ("nist-privacy-1-0:id-ra-p", "soc2-tsc:cc3-2", "related", "partial", "kyora-iq",
     "Privacy risk assessment aligns with SOC 2 CC3.2 (identify and analyze risk)."),
    ("nist-privacy-1-0:gv-po-p", "nist-800-53-r5:pt-1", "related", "strong", "kyora-iq",
     "Privacy governance policies align with NIST privacy authorization policy (PT-1)."),
    ("nist-privacy-1-0:gv-po-p", "soc2-tsc:p1", "related", "partial", "kyora-iq",
     "Privacy governance policies align with the SOC 2 Privacy category."),
    ("nist-privacy-1-0:gv-at-p", "nist-800-53-r5:at-2", "related", "strong", "kyora-iq",
     "Privacy awareness and training aligns with NIST security awareness training (AT-2)."),
    ("nist-privacy-1-0:gv-mt-p", "nist-800-53-r5:ca-7", "related", "strong", "kyora-iq",
     "Privacy monitoring and review aligns with NIST continuous monitoring (CA-7)."),
    ("nist-privacy-1-0:ct-dm-p", "nist-800-53-r5:si-12", "related", "partial", "kyora-iq",
     "Privacy data processing management aligns with NIST information retention (SI-12)."),
    ("nist-privacy-1-0:ct-dm-p", "hipaa-security-rule:310-d-1", "related", "partial", "kyora-iq",
     "Privacy data lifecycle management aligns with HIPAA device and media controls."),
    ("nist-privacy-1-0:ct-dp-p", "nist-800-53-r5:ac-16", "related", "partial", "kyora-iq",
     "Disassociated processing aligns with NIST security and privacy attributes (AC-16)."),
    ("nist-privacy-1-0:cm-aw-p", "nist-ai-600-1:ga-2-7", "related", "partial", "kyora-iq",
     "Data processing awareness relates to generative AI data privacy considerations."),
    ("nist-privacy-1-0:pr-ac-p", "nist-800-53-r5:ac-3", "related", "strong", "kyora-iq",
     "Privacy access control aligns with NIST access enforcement (AC-3)."),
    ("nist-privacy-1-0:pr-ac-p", "soc2-tsc:cc6-1", "related", "strong", "kyora-iq",
     "Privacy access control aligns with SOC 2 CC6.1 (logical access security)."),
    ("nist-privacy-1-0:pr-ac-p", "hipaa-security-rule:312-a-1", "related", "strong", "kyora-iq",
     "Privacy access control aligns with the HIPAA Access Control standard."),
    ("nist-privacy-1-0:pr-ds-p", "nist-800-53-r5:sc-28", "related", "strong", "kyora-iq",
     "Privacy data security aligns with NIST protection of information at rest (SC-28)."),
    ("nist-privacy-1-0:pr-ds-p", "nist-800-53-r5:sc-8", "related", "strong", "kyora-iq",
     "Privacy data-in-transit protection aligns with NIST transmission confidentiality (SC-8)."),
    ("nist-privacy-1-0:pr-ds-p", "hipaa-security-rule:312-e-1", "related", "partial", "kyora-iq",
     "Privacy data-in-transit protection aligns with the HIPAA Transmission Security standard."),
    ("nist-privacy-1-0:pr-po-p", "nist-800-53-r5:cp-9", "related", "partial", "kyora-iq",
     "Privacy protection policies (backups) align with NIST system backup (CP-9)."),
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
        #   SOC 2: the nested 'criterion' nodes (criteria)
        #   others: top-level controls (+ MITRE techniques)
        COUNT_KINDS = {
            "nist-800-53-r5": {"control", "enhancement"},
            "hipaa-security-rule": {"standard"},
            "soc2-tsc": {"criterion"},
            "nist-ai-rmf": {"control"},
            "iso-42001": {"control"},
            "eu-ai-act": {"control"},
            "nist-privacy-1-0": {"control"},
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
