"""
Build the HIPAA Security Rule (45 CFR Part 164, Subpart C) into Kyora schema.

Source text is U.S. federal regulation (public domain). Each standard is a
control; each implementation specification is a child with a
attributes.requirement of "required" or "addressable" — a legally meaningful
distinction defined by the rule itself.

Run:
  python ingestion/build_hipaa.py data/normalized/hipaa-security-rule.json
"""
from __future__ import annotations
import json, sys, datetime
from pathlib import Path

# (section, title, layer, safeguard, [ (spec_section, spec_title, req|addr, text) ])
STANDARDS = [
    ("164.308(a)(1)", "Security Management Process", "governance", "Administrative", [
        ("164.308(a)(1)(ii)(A)", "Risk Analysis", "required",
         "Conduct an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of electronic protected health information."),
        ("164.308(a)(1)(ii)(B)", "Risk Management", "required",
         "Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level."),
        ("164.308(a)(1)(ii)(C)", "Sanction Policy", "required",
         "Apply appropriate sanctions against workforce members who fail to comply with the security policies and procedures."),
        ("164.308(a)(1)(ii)(D)", "Information System Activity Review", "required",
         "Implement procedures to regularly review records of information system activity, such as audit logs, access reports, and security incident tracking reports."),
    ]),
    ("164.308(a)(2)", "Assigned Security Responsibility", "governance", "Administrative", [
        ("164.308(a)(2)", "Assigned Security Responsibility", "required",
         "Identify the security official who is responsible for the development and implementation of the policies and procedures required by the Security Rule."),
    ]),
    ("164.308(a)(3)", "Workforce Security", "governance", "Administrative", [
        ("164.308(a)(3)(ii)(A)", "Authorization and/or Supervision", "addressable",
         "Implement procedures for the authorization and/or supervision of workforce members who work with electronic protected health information or in locations where it might be accessed."),
        ("164.308(a)(3)(ii)(B)", "Workforce Clearance Procedure", "addressable",
         "Implement procedures to determine that the access of a workforce member to electronic protected health information is appropriate."),
        ("164.308(a)(3)(ii)(C)", "Termination Procedures", "addressable",
         "Implement procedures for terminating access to electronic protected health information when employment ends."),
    ]),
    ("164.308(a)(4)", "Information Access Management", "infrastructure", "Administrative", [
        ("164.308(a)(4)(ii)(A)", "Isolating Health Care Clearinghouse Functions", "required",
         "If a clearinghouse is part of a larger organization, implement policies that protect ePHI from unauthorized access by the larger organization."),
        ("164.308(a)(4)(ii)(B)", "Access Authorization", "addressable",
         "Implement policies and procedures for granting access to electronic protected health information."),
        ("164.308(a)(4)(ii)(C)", "Access Establishment and Modification", "addressable",
         "Implement policies and procedures that establish, document, review, and modify a user's right of access to a workstation, transaction, program, or process."),
    ]),
    ("164.308(a)(5)", "Security Awareness and Training", "governance", "Administrative", [
        ("164.308(a)(5)(ii)(A)", "Security Reminders", "addressable",
         "Provide periodic security updates to workforce members."),
        ("164.308(a)(5)(ii)(B)", "Protection from Malicious Software", "addressable",
         "Implement procedures for guarding against, detecting, and reporting malicious software."),
        ("164.308(a)(5)(ii)(C)", "Log-in Monitoring", "addressable",
         "Implement procedures for monitoring log-in attempts and reporting discrepancies."),
        ("164.308(a)(5)(ii)(D)", "Password Management", "addressable",
         "Implement procedures for creating, changing, and safeguarding passwords."),
    ]),
    ("164.308(a)(6)", "Security Incident Procedures", "governance", "Administrative", [
        ("164.308(a)(6)(ii)", "Response and Reporting", "required",
         "Identify and respond to suspected or known security incidents; mitigate harmful effects; and document incidents and their outcomes."),
    ]),
    ("164.308(a)(7)", "Contingency Plan", "governance", "Administrative", [
        ("164.308(a)(7)(ii)(A)", "Data Backup Plan", "required",
         "Establish and implement procedures to create and maintain retrievable exact copies of electronic protected health information."),
        ("164.308(a)(7)(ii)(B)", "Disaster Recovery Plan", "required",
         "Establish and implement procedures to restore any loss of data."),
        ("164.308(a)(7)(ii)(C)", "Emergency Mode Operation Plan", "required",
         "Establish and implement procedures to enable continuation of critical business processes for protection of ePHI while operating in emergency mode."),
        ("164.308(a)(7)(ii)(D)", "Testing and Revision Procedures", "addressable",
         "Implement procedures for periodic testing and revision of contingency plans."),
        ("164.308(a)(7)(ii)(E)", "Applications and Data Criticality Analysis", "addressable",
         "Assess the relative criticality of specific applications and data in support of other contingency plan components."),
    ]),
    ("164.308(a)(8)", "Evaluation", "governance", "Administrative", [
        ("164.308(a)(8)", "Evaluation", "required",
         "Perform a periodic technical and nontechnical evaluation that establishes the extent to which security policies and procedures meet the requirements of the Security Rule."),
    ]),
    ("164.308(b)(1)", "Business Associate Contracts and Other Arrangements", "governance", "Administrative", [
        ("164.308(b)(3)", "Written Contract or Other Arrangement", "required",
         "Document the satisfactory assurances required from a business associate through a written contract or other arrangement that meets the applicable requirements."),
    ]),
    ("164.310(a)(1)", "Facility Access Controls", "infrastructure", "Physical", [
        ("164.310(a)(2)(i)", "Contingency Operations", "addressable",
         "Establish procedures that allow facility access to support restoration of lost data under the disaster recovery and emergency mode operations plans."),
        ("164.310(a)(2)(ii)", "Facility Security Plan", "addressable",
         "Implement policies to safeguard the facility and equipment from unauthorized physical access, tampering, and theft."),
        ("164.310(a)(2)(iii)", "Access Control and Validation Procedures", "addressable",
         "Implement procedures to control and validate a person's access to facilities based on their role or function."),
        ("164.310(a)(2)(iv)", "Maintenance Records", "addressable",
         "Implement policies to document repairs and modifications to the physical components of a facility related to security."),
    ]),
    ("164.310(b)", "Workstation Use", "infrastructure", "Physical", [
        ("164.310(b)", "Workstation Use", "required",
         "Implement policies and procedures that specify the proper functions to be performed and the manner in which to perform them on workstations that access ePHI."),
    ]),
    ("164.310(c)", "Workstation Security", "infrastructure", "Physical", [
        ("164.310(c)", "Workstation Security", "required",
         "Implement physical safeguards for all workstations that access ePHI to restrict access to authorized users."),
    ]),
    ("164.310(d)(1)", "Device and Media Controls", "infrastructure", "Physical", [
        ("164.310(d)(2)(i)", "Disposal", "required",
         "Implement policies and procedures to address the final disposition of ePHI and the hardware or electronic media on which it is stored."),
        ("164.310(d)(2)(ii)", "Media Re-use", "required",
         "Implement procedures for removal of ePHI from electronic media before the media are made available for re-use."),
        ("164.310(d)(2)(iii)", "Accountability", "addressable",
         "Maintain a record of the movements of hardware and electronic media and any person responsible for them."),
        ("164.310(d)(2)(iv)", "Data Backup and Storage", "addressable",
         "Create a retrievable, exact copy of ePHI, when needed, before movement of equipment."),
    ]),
    ("164.312(a)(1)", "Access Control", "infrastructure", "Technical", [
        ("164.312(a)(2)(i)", "Unique User Identification", "required",
         "Assign a unique name and/or number for identifying and tracking user identity."),
        ("164.312(a)(2)(ii)", "Emergency Access Procedure", "required",
         "Establish procedures for obtaining necessary electronic protected health information during an emergency."),
        ("164.312(a)(2)(iii)", "Automatic Logoff", "addressable",
         "Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity."),
        ("164.312(a)(2)(iv)", "Encryption and Decryption", "addressable",
         "Implement a mechanism to encrypt and decrypt electronic protected health information."),
    ]),
    ("164.312(b)", "Audit Controls", "infrastructure", "Technical", [
        ("164.312(b)", "Audit Controls", "required",
         "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information."),
    ]),
    ("164.312(c)(1)", "Integrity", "model", "Technical", [
        ("164.312(c)(2)", "Mechanism to Authenticate ePHI", "addressable",
         "Implement electronic mechanisms to corroborate that electronic protected health information has not been altered or destroyed in an unauthorized manner."),
    ]),
    ("164.312(d)", "Person or Entity Authentication", "infrastructure", "Technical", [
        ("164.312(d)", "Person or Entity Authentication", "required",
         "Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed."),
    ]),
    ("164.312(e)(1)", "Transmission Security", "infrastructure", "Technical", [
        ("164.312(e)(2)(i)", "Integrity Controls", "addressable",
         "Implement security measures to ensure that electronically transmitted ePHI is not improperly modified without detection until disposed of."),
        ("164.312(e)(2)(ii)", "Encryption", "addressable",
         "Implement a mechanism to encrypt electronic protected health information whenever deemed appropriate."),
    ]),
]

def build():
    controls = []
    for section, title, layer, safeguard, specs in STANDARDS:
        node = {
            "id": section.replace("164.", "").replace("(", "-").replace(")", "").replace(".", "-"),
            "display_id": f"§ {section}",
            "title": title,
            "kind": "standard",
            "statement": f"Standard: {title}. ({safeguard} safeguard.)",
            "guidance": "",
            "layer": layer,
            "attributes": {"section": section, "safeguard": safeguard},
            "children": [],
            "mappings": [],
            "source_ref": section,
            "source_handling": "verbatim",
        }
        for spec_section, spec_title, req, text in specs:
            node["children"].append({
                "id": spec_section.replace("164.", "").replace("(", "-").replace(")", "").replace(".", "-"),
                "display_id": f"§ {spec_section}",
                "title": spec_title,
                "kind": "spec",
                "statement": text,
                "guidance": "",
                "layer": layer,
                "attributes": {"section": spec_section, "requirement": req},
                "children": [],
                "mappings": [],
                "source_ref": spec_section,
                "source_handling": "verbatim",
            })
        controls.append(node)
    return {
        "framework": {
            "id": "hipaa-security-rule",
            "name": "HIPAA Security Rule",
            "version": "45 CFR Part 164, Subpart C",
            "publisher": "U.S. Department of Health and Human Services",
            "source_handling": "verbatim",
            "source_url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164",
            "license": "public-domain",
            "retrieved_at": datetime.date.today().isoformat(),
            "source_checksum": "manual:45cfr164-subpartC",
        },
        "controls": controls,
    }

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/normalized/hipaa-security-rule.json"
    data = build()
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(data, indent=2, ensure_ascii=False))
    n_std = len(data["controls"])
    n_spec = sum(len(c["children"]) for c in data["controls"])
    req = sum(1 for c in data["controls"] for s in c["children"] if s["attributes"].get("requirement") == "required")
    addr = sum(1 for c in data["controls"] for s in c["children"] if s["attributes"].get("requirement") == "addressable")
    print(f"standards: {n_std} | specs: {n_spec} | required: {req} | addressable: {addr}")
    print(f"wrote {out}")
