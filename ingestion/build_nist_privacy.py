"""
Build NIST Privacy Framework v1.0 into the Kyora IQ schema.

Source handling: VERBATIM / public domain. NIST publications carry no license
and are free to reproduce (created with U.S. tax dollars). We carry the Core at
the Function -> Category level (the 18 categories), which is the headline level,
mirroring how we treat other frameworks. Category names and identifiers are
factual; descriptions are short plain-language summaries of each category's
intent.

Structure: 5 Functions, 18 Categories, 100 Subcategories (we carry functions +
categories; subcategories are summarized in the category description).
"""
import json, sys, hashlib, datetime

# (function_code, function_name, [(cat_code, cat_name, layer, summary), ...])
FUNCTIONS = [
    ("ID-P", "Identify-P", [
        ("ID.IM-P", "Inventory and Mapping", "governance",
         "Inventory the systems, products, services, and data processing activities, and map data flows, so the organization understands what personal data it handles and where it goes."),
        ("ID.BE-P", "Business Environment", "governance",
         "Understand the organization's role in the data processing ecosystem, its mission, and stakeholders, and align privacy priorities with business objectives."),
        ("ID.RA-P", "Risk Assessment", "governance",
         "Assess the privacy risks to individuals that arise from data processing, including the likelihood and impact of problematic data actions."),
        ("ID.DE-P", "Data Processing Ecosystem Risk Management", "governance",
         "Identify and manage privacy risks that come from third parties, service providers, and partners in the data processing ecosystem."),
    ]),
    ("GV-P", "Govern-P", [
        ("GV.PO-P", "Governance Policies, Processes, and Procedures", "governance",
         "Establish and maintain the organizational privacy values, policies, roles, and legal/regulatory understanding that guide privacy risk management."),
        ("GV.RM-P", "Risk Management Strategy", "governance",
         "Establish the organization's risk tolerance and a strategy for prioritizing and responding to privacy risk."),
        ("GV.AT-P", "Awareness and Training", "governance",
         "Ensure staff and third parties understand their privacy roles, responsibilities, and the organization's privacy policies."),
        ("GV.MT-P", "Monitoring and Review", "governance",
         "Continuously monitor and review the privacy posture, legal environment, and effectiveness of the privacy program, adjusting as needed."),
    ]),
    ("CT-P", "Control-P", [
        ("CT.PO-P", "Data Processing Policies, Processes, and Procedures", "model",
         "Establish policies and procedures that let the organization manage data processing consistent with its privacy strategy, including data minimization and purpose limitation."),
        ("CT.DM-P", "Data Processing Management", "model",
         "Manage data elements through their lifecycle so they can be accessed for review, transmission, alteration, and deletion, and are destroyed according to policy."),
        ("CT.DP-P", "Disassociated Processing", "model",
         "Apply techniques such as de-identification, aggregation, and attribute substitution so processing can occur without unnecessarily linking data to individuals."),
    ]),
    ("CM-P", "Communicate-P", [
        ("CM.PO-P", "Communication Policies, Processes, and Procedures", "output",
         "Establish policies and assign roles for communicating clearly, internally and externally, about the organization's data processing and privacy practices."),
        ("CM.AW-P", "Data Processing Awareness", "output",
         "Enable individuals and stakeholders to understand how data is processed, maintain records of disclosures, and design systems for data processing visibility."),
    ]),
    ("PR-P", "Protect-P", [
        ("PR.PO-P", "Data Protection Policies, Processes, and Procedures", "infrastructure",
         "Maintain data protection policies including configuration change control, backups, response and recovery plans, HR practices, and a vulnerability management plan."),
        ("PR.AC-P", "Identity Management, Authentication, and Access Control", "infrastructure",
         "Limit access to data and devices to authorized users and processes, applying least privilege, separation of duties, and managed remote and physical access."),
        ("PR.DS-P", "Data Security", "infrastructure",
         "Protect data at rest and in transit, guard against data leaks, maintain availability, and use integrity checking for software, firmware, and hardware."),
        ("PR.MA-P", "Maintenance", "infrastructure",
         "Perform maintenance and repairs on systems that process personal data in a controlled, logged, and authorized manner."),
        ("PR.PT-P", "Protective Technology", "infrastructure",
         "Manage protective technology such as removable media restrictions, least functionality, and protected communications and control networks."),
    ]),
]

DISCLAIMER = ("NIST Privacy Framework is voluntary U.S. government guidance and is in the public "
              "domain. Shown here at the Function and Category level for reference; verify against "
              "the official NIST publication. Not legal advice or a compliance determination.")

def node(cid, disp, title, layer, statement, kind, children=None):
    return {"id": cid, "display_id": disp, "title": title, "layer": layer,
            "statement": statement, "guidance": "", "kind": kind,
            "attributes": {}, "children": children or [], "mappings": []}

def build():
    controls = []
    for fcode, fname, cats in FUNCTIONS:
        children = []
        for ccode, cname, layer, summary in cats:
            cid = ccode.lower().replace(".", "-")
            children.append(node(cid, ccode, cname, layer, summary, kind="control"))
        fid = fcode.lower().replace("-", "_")
        controls.append(node(fid, fcode, fname, "governance",
                             f"{fname} function of the NIST Privacy Framework.",
                             kind="function", children=children))
    data = {
        "framework": {
            "id": "nist-privacy-1-0",
            "name": "NIST Privacy Framework",
            "version": "1.0",
            "publisher": "NIST",
            "source_url": "https://www.nist.gov/privacy-framework",
            "source_handling": "verbatim",
            "license": "Public Domain (U.S. Government work)",
            "retrieved_at": datetime.date.today().isoformat(),
            "disclaimer": DISCLAIMER,
        },
        "controls": controls,
    }
    return data

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/normalized/nist-privacy-1-0.json"
    data = build()
    n_cat = sum(len(f["children"]) for f in data["controls"])
    open(out, "w").write(json.dumps(data, indent=2))
    print(f"wrote {out}  ({len(data['controls'])} functions, {n_cat} categories)")
