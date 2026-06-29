"""
Build the wave-3 (licensing-constrained) frameworks into the Kyora schema.

  - SOC 2 / AICPA Trust Services Criteria (2017 TSC, 2022 points of focus)
  - ISO/IEC 42001:2023 Annex A (AI management system controls)
  - HITRUST CSF (control reference structure)
  - EU AI Act (article references)

CRITICAL — these are Bucket 3 ("own wording") sources. The official texts are
copyrighted by AICPA / ISO / HITRUST / the EU. We reproduce ONLY identifiers and
structure (which are facts) and write ENTIRELY our own plain-language
descriptions. No verbatim passages from the official documents. See
docs/SOURCING-POLICY.md.

Run:
  python ingestion/build_wave3.py data/normalized
"""
from __future__ import annotations
import json, sys, datetime
from pathlib import Path

def node(cid, disp, title, layer, statement, kind="criterion", attrs=None, children=None):
    return {
        "id": cid, "display_id": disp, "title": title, "kind": kind,
        "statement": statement, "guidance": "", "layer": layer,
        "attributes": attrs or {}, "children": children or [], "mappings": [],
        "source_ref": disp, "source_handling": "own-wording",
    }

# ---------------------------------------------------------------------------
# SOC 2 — AICPA Trust Services Criteria (Common Criteria CC1-CC9).
# Descriptions are Kyora IQ's own wording. Counts per AICPA TSP Section 100.
# ---------------------------------------------------------------------------
SOC2 = [
    ("cc1", "CC1", "Control Environment", "governance",
     "Foundational governance: integrity and ethical values, board oversight, organizational structure, commitment to competence, and accountability.",
     ["CC1.1 Commitment to integrity and ethical values",
      "CC1.2 Board independence and oversight of internal control",
      "CC1.3 Management establishes structures, reporting lines, and authority",
      "CC1.4 Commitment to attract, develop, and retain competent people",
      "CC1.5 Individuals are held accountable for internal control responsibilities"]),
    ("cc2", "CC2", "Communication and Information", "governance",
     "The entity obtains relevant quality information and communicates it internally and externally to support the functioning of internal control.",
     ["CC2.1 Use of relevant, quality information",
      "CC2.2 Internal communication of objectives and responsibilities",
      "CC2.3 External communication of relevant matters"]),
    ("cc3", "CC3", "Risk Assessment", "governance",
     "The entity specifies objectives, identifies and analyzes risks to those objectives, assesses fraud risk, and evaluates significant change.",
     ["CC3.1 Specify objectives clearly enough to identify risk",
      "CC3.2 Identify and analyze risk to objectives",
      "CC3.3 Consider the potential for fraud",
      "CC3.4 Identify and assess changes that affect internal control"]),
    ("cc4", "CC4", "Monitoring Activities", "governance",
     "The entity selects, develops, and performs ongoing and separate evaluations of internal control, and communicates deficiencies for corrective action.",
     ["CC4.1 Perform ongoing and/or separate evaluations",
      "CC4.2 Evaluate and communicate control deficiencies"]),
    ("cc5", "CC5", "Control Activities", "governance",
     "The entity selects and develops control activities and general technology controls that mitigate risk to acceptable levels, deployed through policies and procedures.",
     ["CC5.1 Select and develop control activities to mitigate risk",
      "CC5.2 Select and develop general controls over technology",
      "CC5.3 Deploy control activities through policies and procedures"]),
    ("cc6", "CC6", "Logical and Physical Access Controls", "infrastructure",
     "The entity restricts logical and physical access, manages identification and authentication, provisions and removes access, and protects against external threats.",
     ["CC6.1 Logical access security over protected information assets",
      "CC6.2 Register and authorize new users; remove access when appropriate",
      "CC6.3 Manage access based on roles and least privilege",
      "CC6.4 Restrict physical access to facilities and assets",
      "CC6.5 Discontinue logical and physical protections on disposal",
      "CC6.6 Protect against threats from outside the system boundary",
      "CC6.7 Restrict the transmission and movement of information",
      "CC6.8 Prevent or detect unauthorized or malicious software"]),
    ("cc7", "CC7", "System Operations", "infrastructure",
     "The entity monitors systems for anomalies, detects and responds to security events and incidents, and recovers from them.",
     ["CC7.1 Detect and monitor for new vulnerabilities and configuration changes",
      "CC7.2 Monitor system components for anomalies",
      "CC7.3 Evaluate security events to determine whether they are incidents",
      "CC7.4 Respond to identified security incidents",
      "CC7.5 Recover from identified security incidents"]),
    ("cc8", "CC8", "Change Management", "infrastructure",
     "The entity authorizes, designs, develops, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
     ["CC8.1 Manage changes to infrastructure, data, software, and procedures"]),
    ("cc9", "CC9", "Risk Mitigation", "governance",
     "The entity identifies, selects, and develops risk mitigation activities, including for business disruptions and vendor/business-partner relationships.",
     ["CC9.1 Identify and develop risk mitigation activities",
      "CC9.2 Assess and manage risks from vendors and business partners"]),
]

# ---------------------------------------------------------------------------
# ISO/IEC 42001:2023 Annex A — 9 control objectives (A.2-A.10), own wording.
# ---------------------------------------------------------------------------
ISO42001 = [
    ("a2", "A.2", "AI Policy", "governance",
     "Establish, document, and maintain an organizational policy for the development and use of AI systems, aligned with business objectives and other policies."),
    ("a3", "A.3", "Internal Organization", "governance",
     "Define AI roles and responsibilities and establish a process for reporting concerns about the organization's AI systems."),
    ("a4", "A.4", "Resources for AI Systems", "model",
     "Identify and document the resources — data, tooling, compute, human competence — needed across the AI system lifecycle."),
    ("a5", "A.5", "AI System Impact Assessment", "governance",
     "Establish a process to assess the potential impacts of AI systems on individuals, groups, and society throughout their lifecycle."),
    ("a6", "A.6", "AI System Lifecycle", "model",
     "Define and apply responsible processes for the design, development, verification, deployment, operation, and retirement of AI systems."),
    ("a7", "A.7", "Data for AI Systems", "model",
     "Manage data used in AI systems: provenance, quality, preparation, and governance appropriate to the system's purpose."),
    ("a8", "A.8", "Information for Interested Parties", "output",
     "Provide appropriate information to users and affected parties about AI system capabilities, limitations, and intended use."),
    ("a9", "A.9", "Use of AI Systems", "agentic",
     "Establish responsible-use objectives and controls for how AI systems are operated and consumed within and beyond the organization."),
    ("a10", "A.10", "Third-Party and Customer Relationships", "governance",
     "Manage AI-related responsibilities, risks, and obligations across suppliers, partners, and customers in the AI value chain."),
]

# ---------------------------------------------------------------------------
# HITRUST CSF — representative control reference structure, own wording.
# ---------------------------------------------------------------------------
HITRUST = [
    ("01-access-control", "01 Access Control", "Access Control", "infrastructure",
     "Govern logical access: registration, privilege management, authentication, and review of user access to information systems."),
    ("06-config-management", "06 Configuration Management", "Configuration Management", "infrastructure",
     "Establish and maintain secure baseline configurations and control changes to systems and software."),
    ("07-vuln-management", "07 Vulnerability Management", "Vulnerability Management", "infrastructure",
     "Identify, evaluate, and remediate technical vulnerabilities in a timely, risk-based manner."),
    ("09-audit-logging", "09 Audit Logging & Monitoring", "Audit Logging and Monitoring", "infrastructure",
     "Record and review security-relevant events to detect and investigate unauthorized activity."),
    ("11-incident-management", "11 Incident Management", "Incident Management", "governance",
     "Detect, report, respond to, and learn from information security incidents."),
    ("13-privacy", "13 Privacy Practices", "Privacy Practices", "output",
     "Govern the collection, use, disclosure, retention, and protection of personal information."),
]

# ---------------------------------------------------------------------------
# EU AI Act — article references with Kyora summaries (law text is public; we
# summarize and link rather than reproduce long passages).
# ---------------------------------------------------------------------------
EU_AI_ACT = [
    ("art-9", "Art. 9", "Risk Management System", "governance",
     "High-risk AI systems must establish, implement, and maintain a continuous risk management system across the lifecycle."),
    ("art-10", "Art. 10", "Data and Data Governance", "model",
     "Training, validation, and testing data for high-risk AI must meet quality and governance criteria, including bias examination."),
    ("art-12", "Art. 12", "Record-Keeping (Logging)", "infrastructure",
     "High-risk AI systems must automatically record events (logs) over their lifetime to ensure traceability."),
    ("art-13", "Art. 13", "Transparency and Information to Users", "output",
     "High-risk AI systems must be transparent enough for deployers to interpret output and use the system appropriately."),
    ("art-14", "Art. 14", "Human Oversight", "agentic",
     "High-risk AI systems must be designed to allow effective human oversight that can prevent or minimize risks."),
    ("art-15", "Art. 15", "Accuracy, Robustness and Cybersecurity", "model",
     "High-risk AI systems must achieve appropriate levels of accuracy, robustness, and cybersecurity, and perform consistently."),
]

def soc2_controls():
    out = []
    for cid, disp, title, layer, summary, pofs in SOC2:
        children = []
        for i, pof in enumerate(pofs, 1):
            code = pof.split(" ", 1)[0]
            text = pof.split(" ", 1)[1]
            children.append(node(f"{cid}-{i}", code, text, layer,
                                  text, kind="criterion"))
        out.append(node(cid, disp, title, layer, summary, kind="criterion", children=children))
    return out

def simple_controls(rows):
    return [node(cid, disp, title, layer, statement, kind="control")
            for (cid, disp, title, layer, statement) in rows]

def wrap(fid, name, version, publisher, url, controls):
    return {
        "framework": {
            "id": fid, "name": name, "version": version, "publisher": publisher,
            "source_handling": "own-wording", "source_url": url,
            "license": "proprietary-structure-only",
            "retrieved_at": datetime.date.today().isoformat(),
            "source_checksum": f"manual:{fid}",
        },
        "controls": controls,
    }

def build_all(outdir):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    files = {
        "soc2-tsc": wrap("soc2-tsc", "SOC 2 (AICPA Trust Services Criteria)",
                         "2017 TSC / 2022 PoF", "AICPA",
                         "https://www.aicpa-cima.com/", soc2_controls()),
        "iso-42001": wrap("iso-42001", "ISO/IEC 42001:2023 (AI Management System)",
                          "2023", "ISO/IEC", "https://www.iso.org/standard/81230.html",
                          simple_controls(ISO42001)),
        "hitrust-csf": wrap("hitrust-csf", "HITRUST CSF",
                            "v11 (representative)", "HITRUST",
                            "https://hitrustalliance.net/", simple_controls(HITRUST)),
        "eu-ai-act": wrap("eu-ai-act", "EU AI Act",
                          "Regulation (EU) 2024/1689", "European Union",
                          "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
                          simple_controls(EU_AI_ACT)),
    }
    for fid, data in files.items():
        p = Path(outdir) / f"{fid}.json"
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        n = sum(1 + len(c["children"]) for c in data["controls"])
        print(f"wrote {p}  ({len(data['controls'])} controls, {n} nodes)")

if __name__ == "__main__":
    build_all(sys.argv[1] if len(sys.argv) > 1 else "data/normalized")
