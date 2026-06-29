"""
Build the remaining wave-1 frameworks into Kyora schema:
  - OWASP Top 10 for LLM Applications (2025)   paraphrased, CC BY-SA
  - OWASP API Security Top 10 (2023)           paraphrased, CC BY-SA
  - OWASP Top 10 (Web, 2021)                   paraphrased, CC BY-SA
  - NIST AI RMF (AI 100-1)                      verbatim summary, public domain
  - NIST AI 600-1 (Generative AI Profile)      verbatim summary, public domain

Identifiers and short titles are facts and are carried as-is; longer descriptions
are Kyora IQ's own concise wording (see docs/SOURCING-POLICY.md).

Run:
  python ingestion/build_owasp_nistai.py data/normalized
"""
from __future__ import annotations
import json, sys, datetime
from pathlib import Path

def node(cid, disp, title, layer, statement, attrs=None):
    return {
        "id": cid, "display_id": disp, "title": title, "kind": "risk" if disp.startswith(("LLM","API","A0")) else "control",
        "statement": statement, "guidance": "", "layer": layer,
        "attributes": attrs or {}, "children": [], "mappings": [],
        "source_ref": disp, "source_handling": "paraphrased",
    }

OWASP_LLM = [
    ("llm01-2025","LLM01:2025","Prompt Injection","input","Crafted input overrides the model's instructions, directly or through poisoned content it reads from RAG, files, or the web, to exfiltrate data, bypass safeguards, or trigger unintended tool actions."),
    ("llm02-2025","LLM02:2025","Sensitive Information Disclosure","output","The model exposes private, regulated, or proprietary data through outputs, logs, embeddings, or cached conversations."),
    ("llm03-2025","LLM03:2025","Supply Chain","model","Weaknesses in base models, datasets, libraries, plugins, or infrastructure compromise the whole application."),
    ("llm04-2025","LLM04:2025","Data and Model Poisoning","model","Tampered training, fine-tuning, or RAG data introduces bias, backdoors, or degraded behavior."),
    ("llm05-2025","LLM05:2025","Improper Output Handling","output","Model output passed downstream without validation enables injection, XSS, or code execution in connected systems."),
    ("llm06-2025","LLM06:2025","Excessive Agency","agentic","An agent granted too much autonomy, tooling, or permission can take damaging actions when manipulated."),
    ("llm07-2025","LLM07:2025","System Prompt Leakage","output","Sensitive information embedded in system prompts (rules, credentials, logic) is exposed to users."),
    ("llm08-2025","LLM08:2025","Vector and Embedding Weaknesses","input","RAG retrieval and embedding stores are manipulated or leak data via poisoned documents, embedding inversion, or cross-tenant retrieval."),
    ("llm09-2025","LLM09:2025","Misinformation","output","The model produces false or misleading output that users over-trust, leading to bad decisions and liability."),
    ("llm10-2025","LLM10:2025","Unbounded Consumption","infrastructure","Uncontrolled resource usage causes denial of service, runaway cost ('denial of wallet'), or model replication."),
]

OWASP_API = [
    ("api1-2023","API1:2023","Broken Object Level Authorization","infrastructure","An API exposes object identifiers without verifying the caller is authorized for that specific object, enabling unauthorized data access."),
    ("api2-2023","API2:2023","Broken Authentication","infrastructure","Authentication mechanisms are implemented incorrectly, letting attackers assume other identities."),
    ("api3-2023","API3:2023","Broken Object Property Level Authorization","infrastructure","Excessive data exposure or mass assignment lets callers read or modify properties they should not."),
    ("api4-2023","API4:2023","Unrestricted Resource Consumption","infrastructure","Missing rate and resource limits allow denial of service or cost-based abuse."),
    ("api5-2023","API5:2023","Broken Function Level Authorization","infrastructure","Authorization checks miss at the function/endpoint level, exposing privileged operations."),
    ("api6-2023","API6:2023","Unrestricted Access to Sensitive Business Flows","infrastructure","Business flows are exposed without protection against automated abuse."),
    ("api7-2023","API7:2023","Server Side Request Forgery","infrastructure","An API fetches a remote resource from a user-supplied URL without validation, enabling SSRF."),
    ("api8-2023","API8:2023","Security Misconfiguration","infrastructure","Insecure defaults, incomplete configurations, or verbose errors weaken the API."),
    ("api9-2023","API9:2023","Improper Inventory Management","governance","Undocumented or outdated API versions and endpoints widen the attack surface."),
    ("api10-2023","API10:2023","Unsafe Consumption of APIs","infrastructure","Trusting third-party API data without validation propagates their weaknesses into your system."),
]

OWASP_WEB = [
    ("a01-2021","A01:2021","Broken Access Control","infrastructure","Restrictions on authenticated users are not properly enforced, allowing unauthorized access to data or functions."),
    ("a02-2021","A02:2021","Cryptographic Failures","infrastructure","Sensitive data is exposed due to weak, missing, or misused cryptography."),
    ("a03-2021","A03:2021","Injection","input","Untrusted input is interpreted as a command or query (SQL, OS, LDAP, etc.), including cross-site scripting."),
    ("a04-2021","A04:2021","Insecure Design","governance","Missing or ineffective security controls by design, not merely implementation bugs."),
    ("a05-2021","A05:2021","Security Misconfiguration","infrastructure","Insecure defaults, incomplete setup, or overly verbose errors expose the application."),
    ("a06-2021","A06:2021","Vulnerable and Outdated Components","model","Use of components with known vulnerabilities or that are unsupported/out of date."),
    ("a07-2021","A07:2021","Identification and Authentication Failures","infrastructure","Weaknesses in confirming user identity, session management, or credential handling."),
    ("a08-2021","A08:2021","Software and Data Integrity Failures","model","Code and infrastructure that does not protect against integrity violations, e.g. insecure deserialization or unverified updates."),
    ("a09-2021","A09:2021","Security Logging and Monitoring Failures","infrastructure","Insufficient logging and monitoring delays breach detection and response."),
    ("a10-2021","A10:2021","Server-Side Request Forgery","infrastructure","The server fetches a user-supplied URL without validating it, enabling SSRF."),
]

def nist_node(cid, disp, title, layer, statement, function):
    n = node(cid, disp, title, layer, statement, {"function": function})
    n["kind"] = "control"
    n["source_handling"] = "verbatim"
    return n

NIST_AI_RMF = [
    ("govern-1-1","GOVERN 1.1","Legal and Regulatory Requirements","governance","Legal and regulatory requirements involving AI are understood, managed, and documented.","GOVERN"),
    ("govern-1-2","GOVERN 1.2","Trustworthy AI Characteristics","governance","The characteristics of trustworthy AI are integrated into organizational policies, processes, and procedures.","GOVERN"),
    ("govern-2-1","GOVERN 2.1","Roles and Responsibilities","governance","Roles, responsibilities, and lines of communication related to mapping, measuring, and managing AI risks are documented and clear.","GOVERN"),
    ("map-1-1","MAP 1.1","Context and Intended Purpose","governance","Intended purpose, setting, and context of the AI system are understood and documented.","MAP"),
    ("map-2-3","MAP 2.3","Capabilities and Limitations","model","Scientific integrity and the system's capabilities, limitations, and assumptions are documented.","MAP"),
    ("measure-2-7","MEASURE 2.7","Security and Resilience","input","AI system security and resilience are evaluated and documented, including against adversarial inputs.","MEASURE"),
    ("measure-2-11","MEASURE 2.11","Harmful Bias","model","Fairness and bias are evaluated and results documented.","MEASURE"),
    ("manage-2-2","MANAGE 2.2","Mechanisms to Sustain Value","governance","Mechanisms are in place to sustain the value of deployed AI systems and to manage risk over time.","MANAGE"),
    ("manage-4-1","MANAGE 4.1","Post-Deployment Monitoring","output","Post-deployment monitoring plans are implemented, including mechanisms for incident response and recovery.","MANAGE"),
]

NIST_AI_600 = [
    ("ga-2-1","GAI 2.1","CBRN Information","governance","Manage risks that generative AI could lower barriers to access to harmful CBRN-related information.","risk"),
    ("ga-2-7","GAI 2.7","Data Privacy","output","Manage risks of generative AI leaking or inferring sensitive personal data.","risk"),
    ("ga-2-8","GAI 2.8","Confabulation","output","Manage risks of generative AI producing confidently stated false content (confabulation/hallucination).","risk"),
    ("ga-2-9","GAI 2.9","Information Security","input","Manage generative-AI information-security risks including prompt injection and data poisoning.","risk"),
    ("ga-2-12","GAI 2.12","Value Chain and Component Integration","model","Manage risks arising from third-party models, data, and components in the generative-AI value chain.","risk"),
]

def wrap(fid, name, version, publisher, handling, url, license_, controls):
    return {
        "framework": {
            "id": fid, "name": name, "version": version, "publisher": publisher,
            "source_handling": handling, "source_url": url, "license": license_,
            "retrieved_at": datetime.date.today().isoformat(),
            "source_checksum": f"manual:{fid}",
        },
        "controls": controls,
    }

def build_all(outdir: str):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    files = {
        "owasp-llm-top10": wrap("owasp-llm-top10","OWASP Top 10 for LLM Applications","2025","OWASP","paraphrased","https://genai.owasp.org/llm-top-10/","CC-BY-SA-4.0",[node(*r) for r in OWASP_LLM]),
        "owasp-api-top10": wrap("owasp-api-top10","OWASP API Security Top 10","2023","OWASP","paraphrased","https://owasp.org/API-Security/","CC-BY-SA-4.0",[node(*r) for r in OWASP_API]),
        "owasp-web-top10": wrap("owasp-web-top10","OWASP Top 10","2021","OWASP","paraphrased","https://owasp.org/Top10/","CC-BY-SA-4.0",[node(*r) for r in OWASP_WEB]),
        "nist-ai-rmf": wrap("nist-ai-rmf","NIST AI Risk Management Framework","AI 100-1","NIST","verbatim","https://www.nist.gov/itl/ai-risk-management-framework","public-domain",[nist_node(*r) for r in NIST_AI_RMF]),
        "nist-ai-600-1": wrap("nist-ai-600-1","NIST AI 600-1 Generative AI Profile","600-1","NIST","verbatim","https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf","public-domain",[nist_node(c,d,t,l,s,f) for (c,d,t,l,s,f) in NIST_AI_600]),
    }
    for fid, data in files.items():
        p = Path(outdir) / f"{fid}.json"
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"wrote {p}  ({len(data['controls'])} controls)")

if __name__ == "__main__":
    build_all(sys.argv[1] if len(sys.argv) > 1 else "data/normalized")
