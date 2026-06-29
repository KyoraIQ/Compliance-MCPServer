"""
Normalize MITRE ATLAS (official atlas-data YAML) into the Kyora schema.

MITRE content is used under MITRE's terms with attribution. Technique IDs and
names are facts and are carried as-is; descriptions are paraphrased to a concise
summary (we do not reproduce MITRE's full prose). Each tactic becomes a parent
control; its techniques become children; sub-techniques nest under their parent.

Run:
  python ingestion/normalize_atlas.py data/raw/atlas.yaml data/normalized/mitre-atlas.json
"""
from __future__ import annotations
import sys, hashlib, datetime, re
from pathlib import Path
import yaml

# ATLAS tactic -> Kyora layer (AI attack stages mapped to our stack layers)
TACTIC_LAYER = {
    "Reconnaissance": "governance",
    "Resource Development": "governance",
    "Initial Access": "infrastructure",
    "AI Model Access": "model",
    "Execution": "infrastructure",
    "Persistence": "infrastructure",
    "Privilege Escalation": "infrastructure",
    "Defense Evasion": "output",
    "Credential Access": "infrastructure",
    "Discovery": "infrastructure",
    "Lateral Movement": "infrastructure",
    "Collection": "output",
    "AI Attack Staging": "input",
    "Command and Control": "agentic",
    "Exfiltration": "output",
    "Impact": "output",
}

def paraphrase(desc: str, limit: int = 320) -> str:
    """Condense MITRE prose to a concise neutral summary (first sentences)."""
    text = re.sub(r"\s+", " ", (desc or "").strip())
    # take up to the first 2 sentences, capped at limit chars
    sentences = re.split(r"(?<=[.!?])\s+", text)
    out = ""
    for s in sentences:
        if len(out) + len(s) > limit and out:
            break
        out = (out + " " + s).strip()
    return out

def slug(s: str) -> str:
    return s.lower().replace(".", "-").replace(" ", "-")

def main(src: str, out: str):
    raw = Path(src).read_bytes()
    checksum = "sha256:" + hashlib.sha256(raw).hexdigest()
    data = yaml.safe_load(raw)
    matrix = data["matrices"][0]
    version = data.get("version", "?")

    tactics = matrix["tactics"]
    techniques = matrix["techniques"]
    tactic_name = {t["id"]: t["name"] for t in tactics}

    # group techniques by tactic; nest sub-techniques under parents
    by_id = {t["id"]: t for t in techniques}
    children_of = {}
    roots = []
    for t in techniques:
        parent = t.get("subtechnique-of")
        if parent:
            children_of.setdefault(parent, []).append(t)
        else:
            roots.append(t)

    def tech_node(t):
        att = t.get("ATT&CK-reference")
        attrs = {"tactics": [tactic_name.get(x, x) for x in t.get("tactics", [])],
                 "maturity": t.get("maturity", "")}
        if att:
            attrs["attack_reference"] = att.get("id") if isinstance(att, dict) else att
        node = {
            "id": slug(t["id"]),
            "display_id": t["id"],
            "title": t["name"],
            "kind": "technique" if not t.get("subtechnique-of") else "subtechnique",
            "statement": paraphrase(t.get("description", "")),
            "guidance": "",
            "layer": TACTIC_LAYER.get(attrs["tactics"][0], "model") if attrs["tactics"] else "model",
            "attributes": attrs,
            "children": [tech_node(c) for c in sorted(children_of.get(t["id"], []), key=lambda x: x["id"])],
            "mappings": [],
            "source_ref": t["id"],
            "source_handling": "paraphrased",
        }
        return node

    # one control per tactic, techniques as children
    controls = []
    for ta in tactics:
        layer = TACTIC_LAYER.get(ta["name"], "model")
        tac_techs = [t for t in roots if ta["id"] in t.get("tactics", [])]
        node = {
            "id": slug(ta["id"]),
            "display_id": ta["id"],
            "title": ta["name"],
            "kind": "tactic",
            "statement": paraphrase(ta.get("description", "")),
            "guidance": "",
            "layer": layer,
            "attributes": {"tactic": ta["name"]},
            "children": [tech_node(t) for t in sorted(tac_techs, key=lambda x: x["id"])],
            "mappings": [],
            "source_ref": ta["id"],
            "source_handling": "paraphrased",
        }
        controls.append(node)

    out_data = {
        "framework": {
            "id": "mitre-atlas",
            "name": "MITRE ATLAS",
            "version": str(version),
            "publisher": "The MITRE Corporation",
            "source_handling": "paraphrased",
            "source_url": "https://github.com/mitre-atlas/atlas-data",
            "license": "MITRE-ATLAS-terms",
            "retrieved_at": datetime.date.today().isoformat(),
            "source_checksum": checksum,
        },
        "controls": controls,
    }
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(__import__("json").dumps(out_data, indent=2, ensure_ascii=False))

    def count(nodes):
        n = len(nodes)
        for x in nodes: n += count(x["children"])
        return n
    print(f"tactics: {len(controls)} | total nodes: {count(controls)} | version {version}")
    print(f"wrote {out}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
