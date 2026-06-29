"""
Build a curated MITRE ATT&CK (Enterprise) subset into the Kyora schema.

Rationale: full ATT&CK has 600+ techniques, most irrelevant to a control
crosswalk. We carry the techniques that map meaningfully to the security and
privacy controls Kyora IQ tracks, organized by tactic. Technique IDs and names
are MITRE's (carried verbatim, with attribution); descriptions are Kyora IQ's own
concise summaries. Expand this list as mappings warrant.

Run:
  python ingestion/build_attack.py data/normalized/mitre-attack.json
"""
from __future__ import annotations
import json, sys, datetime
from pathlib import Path

# tactic -> Kyora layer
TACTIC_LAYER = {
    "Initial Access": "infrastructure", "Execution": "infrastructure",
    "Persistence": "infrastructure", "Privilege Escalation": "infrastructure",
    "Defense Evasion": "output", "Credential Access": "infrastructure",
    "Discovery": "infrastructure", "Collection": "output",
    "Exfiltration": "output", "Impact": "output",
}

# (technique_id, name, tactic, summary)
TECHNIQUES = [
    ("T1190", "Exploit Public-Facing Application", "Initial Access",
     "Adversaries exploit a weakness in an internet-facing host or application to gain initial access."),
    ("T1078", "Valid Accounts", "Initial Access",
     "Adversaries use legitimate credentials to gain access, persist, escalate, or evade detection."),
    ("T1110", "Brute Force", "Credential Access",
     "Adversaries systematically guess passwords or keys to obtain valid credentials."),
    ("T1556", "Modify Authentication Process", "Credential Access",
     "Adversaries tamper with authentication mechanisms to bypass or weaken access controls."),
    ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
     "Adversaries exploit software vulnerabilities to gain higher-level permissions."),
    ("T1098", "Account Manipulation", "Persistence",
     "Adversaries modify accounts (add credentials, change permissions) to maintain access."),
    ("T1530", "Data from Cloud Storage", "Collection",
     "Adversaries access data objects from improperly secured cloud storage."),
    ("T1213", "Data from Information Repositories", "Collection",
     "Adversaries mine information repositories (wikis, ticketing, code) for sensitive data."),
    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
     "Adversaries steal data over a different protocol than the main command channel."),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration",
     "Adversaries exfiltrate data to a legitimate external web service to blend with normal traffic."),
    ("T1485", "Data Destruction", "Impact",
     "Adversaries destroy data and files to interrupt availability or operations."),
    ("T1499", "Endpoint Denial of Service", "Impact",
     "Adversaries exhaust a system's resources to deny availability to legitimate users."),
    ("T1562", "Impair Defenses", "Defense Evasion",
     "Adversaries disable or modify security tools, logging, or controls to avoid detection."),
    ("T1070", "Indicator Removal", "Defense Evasion",
     "Adversaries delete or modify artifacts such as logs to remove evidence of activity."),
    ("T1046", "Network Service Discovery", "Discovery",
     "Adversaries enumerate network services to find systems and plan further actions."),
    ("T1203", "Exploitation for Client Execution", "Execution",
     "Adversaries exploit client software vulnerabilities to execute code."),
]

def build():
    by_tactic = {}
    for tid, name, tactic, summary in TECHNIQUES:
        by_tactic.setdefault(tactic, []).append((tid, name, summary))
    controls = []
    for tactic, items in by_tactic.items():
        layer = TACTIC_LAYER.get(tactic, "infrastructure")
        node = {
            "id": tactic.lower().replace(" ", "-"),
            "display_id": tactic,
            "title": tactic,
            "kind": "tactic",
            "statement": f"ATT&CK tactic: {tactic}.",
            "guidance": "",
            "layer": layer,
            "attributes": {"tactic": tactic},
            "children": [{
                "id": tid.lower(),
                "display_id": tid,
                "title": name,
                "kind": "technique",
                "statement": summary,
                "guidance": "",
                "layer": layer,
                "attributes": {"tactic": tactic},
                "children": [],
                "mappings": [],
                "source_ref": tid,
                "source_handling": "paraphrased",
            } for tid, name, summary in items],
            "mappings": [],
            "source_ref": tactic,
            "source_handling": "paraphrased",
        }
        controls.append(node)
    return {
        "framework": {
            "id": "mitre-attack",
            "name": "MITRE ATT&CK (Enterprise, curated)",
            "version": "curated-subset",
            "publisher": "The MITRE Corporation",
            "source_handling": "paraphrased",
            "source_url": "https://attack.mitre.org/",
            "license": "MITRE-ATTACK-terms",
            "retrieved_at": datetime.date.today().isoformat(),
            "source_checksum": "manual:attack-curated",
        },
        "controls": controls,
    }

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/normalized/mitre-attack.json"
    data = build()
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(data, indent=2, ensure_ascii=False))
    n = sum(1 + len(c["children"]) for c in data["controls"])
    print(f"tactics: {len(data['controls'])} | techniques: {len(TECHNIQUES)} | nodes: {n}")
    print(f"wrote {out}")
