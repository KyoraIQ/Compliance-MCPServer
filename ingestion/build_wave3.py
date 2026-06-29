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
# HITRUST CSF v11 — full 14 control categories (0.0-0.13) and their 49
# objectives. Own wording (structure is fact; HITRUST text is licensed).
# Format: (cat_id, cat_display, cat_title, layer, [ (obj_id, obj_title) ])
# ---------------------------------------------------------------------------
HITRUST = [
    ("00", "0.0", "Information Security Management Program", "governance", [
        ("00.a", "Information Security Management Program")]),
    ("01", "1.0", "Access Control", "infrastructure", [
        ("01.a", "Business Requirement for Access Control"),
        ("01.b", "Authorized Access to Information Systems"),
        ("01.c", "User Responsibilities"),
        ("01.d", "Network Access Control"),
        ("01.e", "Operating System Access Control"),
        ("01.f", "Application and Information Access Control"),
        ("01.g", "Mobile Computing and Teleworking")]),
    ("02", "2.0", "Human Resources Security", "governance", [
        ("02.a", "Prior to Employment"),
        ("02.b", "During Employment"),
        ("02.c", "Termination or Change of Employment")]),
    ("03", "3.0", "Risk Management", "governance", [
        ("03.a", "Risk Management Program"),
        ("03.b", "Performing Risk Assessments"),
        ("03.c", "Risk Mitigation")]),
    ("04", "4.0", "Security Policy", "governance", [
        ("04.a", "Information Security Policy"),
        ("04.b", "Review of the Information Security Policy")]),
    ("05", "5.0", "Organization of Information Security", "governance", [
        ("05.a", "Internal Organization"),
        ("05.b", "External Parties")]),
    ("06", "6.0", "Compliance", "governance", [
        ("06.a", "Compliance with Legal Requirements"),
        ("06.b", "Compliance with Security Policies and Standards"),
        ("06.c", "Information System Audit Considerations")]),
    ("07", "7.0", "Asset Management", "infrastructure", [
        ("07.a", "Responsibility for Assets"),
        ("07.b", "Information Classification")]),
    ("08", "8.0", "Physical and Environmental Security", "infrastructure", [
        ("08.a", "Secure Areas"),
        ("08.b", "Equipment Security")]),
    ("09", "9.0", "Communications and Operations Management", "infrastructure", [
        ("09.a", "Documented Operating Procedures"),
        ("09.b", "Change Management"),
        ("09.c", "Segregation of Duties"),
        ("09.d", "Third-Party Service Delivery Management"),
        ("09.e", "System Planning and Acceptance"),
        ("09.f", "Protection Against Malicious and Mobile Code"),
        ("09.g", "Information Back-Up"),
        ("09.h", "Network Security Management"),
        ("09.i", "Media Handling"),
        ("09.j", "Exchange of Information")]),
    ("10", "10.0", "Information Systems Acquisition, Development, and Maintenance", "model", [
        ("10.a", "Security Requirements of Information Systems"),
        ("10.b", "Correct Processing in Applications"),
        ("10.c", "Cryptographic Controls"),
        ("10.d", "Security of System Files"),
        ("10.e", "Security in Development and Support Processes"),
        ("10.f", "Technical Vulnerability Management")]),
    ("11", "11.0", "Information Security Incident Management", "governance", [
        ("11.a", "Reporting Information Security Events and Weaknesses"),
        ("11.b", "Management of Information Security Incidents and Improvements")]),
    ("12", "12.0", "Business Continuity Management", "governance", [
        ("12.a", "Information Security Aspects of Business Continuity Management")]),
    ("13", "13.0", "Privacy Practices", "output", [
        ("13.a", "Openness and Transparency"),
        ("13.b", "Individual Participation"),
        ("13.c", "Purpose Specification and Limitation"),
        ("13.d", "Data Minimization"),
        ("13.e", "Use and Disclosure Limitation"),
        ("13.f", "Data Quality and Integrity"),
        ("13.g", "Accountability and Privacy Management")]),
]

def hitrust_controls():
    out = []
    for cat_id, disp, title, layer, objectives in HITRUST:
        children = []
        for obj_id, obj_title in objectives:
            children.append(node(obj_id, obj_id, obj_title, layer,
                f"Control objective within HITRUST CSF category {disp} {title}. "
                f"(Structure shown; HITRUST control text is licensed — see disclaimer.)",
                kind="criterion"))
        out.append(node(cat_id, disp, title, layer,
            f"HITRUST CSF control category {disp}: {title}.",
            kind="control", children=children))
    return out

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

DISCLAIMERS = {
    "soc2-tsc": "The Trust Services Criteria and COSO Principles are proprietary to the AICPA. This tool provides independently-written summaries for educational reference only and is not affiliated with or endorsed by the AICPA. For official criteria text, audit guidance, and SOC 2 reports, visit the AICPA website. Do not rely on this tool for compliance decisions.",
    "iso-42001": "ISO/IEC 42001 is copyrighted by ISO/IEC. This tool provides independently-written summaries of the control structure for educational reference only and is not affiliated with or endorsed by ISO/IEC. Purchase the official standard from ISO for authoritative control text. Do not rely on this tool for compliance decisions.",
    "hitrust-csf": "The HITRUST CSF is proprietary to HITRUST. This tool provides independently-written summaries of the control structure for educational reference only and is not affiliated with or endorsed by HITRUST. Access the official CSF via HITRUST MyCSF for authoritative control text. Do not rely on this tool for compliance decisions.",
    "eu-ai-act": "Summaries of EU AI Act articles are independently written for educational reference. The official, legally binding text is published in the Official Journal of the European Union (Regulation (EU) 2024/1689). Do not rely on this tool for legal or compliance decisions.",
}

def wrap(fid, name, version, publisher, url, controls):
    return {
        "framework": {
            "id": fid, "name": name, "version": version, "publisher": publisher,
            "source_handling": "own-wording", "source_url": url,
            "license": "proprietary-structure-only",
            "disclaimer": DISCLAIMERS.get(fid, ""),
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
                            "v11", "HITRUST",
                            "https://hitrustalliance.net/", hitrust_controls()),
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
