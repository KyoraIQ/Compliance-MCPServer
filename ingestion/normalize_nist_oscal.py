"""
Normalize NIST OSCAL catalogs (800-53, and AI publications where OSCAL exists)
into the Kyora IQ control schema defined in docs/DATA-MODEL.md.

OSCAL shape we consume:
  catalog.groups[].controls[]            -> base controls
  control.parts[name=statement].parts[]  -> lettered sub-parts a./b./c.
  control.parts[name=guidance].prose     -> guidance text
  control.controls[]                     -> enhancements (AC-2.1 etc.), recursive

Run:
  python ingestion/normalize_nist_oscal.py \
      data/raw/nist_800_53_catalog.json \
      data/normalized/nist-800-53-r5.json
"""
from __future__ import annotations
import json, sys, hashlib, datetime, re
from pathlib import Path

# Map NIST control family (group id) -> Kyora layer. Families that are about
# policy/program management map to governance; technical families to their layer.
FAMILY_LAYER = {
    "ac": "infrastructure", "au": "infrastructure", "ia": "infrastructure",
    "sc": "infrastructure", "cm": "infrastructure", "ma": "infrastructure",
    "si": "output", "si-llm": "output",
    "ra": "governance", "pl": "governance", "pm": "governance",
    "ca": "governance", "at": "governance", "ps": "governance",
    "ir": "governance", "cp": "governance", "mp": "infrastructure",
    "pe": "infrastructure", "sa": "governance", "sr": "governance",
    "ac-2": "infrastructure", "pt": "governance",
}

def _prose_of(part: dict) -> str:
    """Collect prose from a part and its descendants into readable text."""
    chunks = []
    if part.get("prose"):
        chunks.append(part["prose"].strip())
    for sub in part.get("parts", []) or []:
        label = ""
        for pr in sub.get("props", []) or []:
            if pr.get("name") == "label":
                label = pr.get("value", "")
        sub_text = _prose_of(sub)
        if sub_text:
            chunks.append(f"{label} {sub_text}".strip())
    return "\n".join(c for c in chunks if c)

def _label(node: dict) -> str:
    for pr in node.get("props", []) or []:
        if pr.get("name") == "label":
            return pr.get("value", "")
    return ""

def _statement(control: dict) -> str:
    for p in control.get("parts", []) or []:
        if p.get("name") == "statement":
            return _prose_of(p)
    return ""

def _guidance(control: dict) -> str:
    for p in control.get("parts", []) or []:
        if p.get("name") == "guidance":
            return _prose_of(p)
    return ""

def _statement_children(control: dict) -> list:
    """Lettered sub-parts a./b./c. of the statement become child nodes."""
    kids = []
    for p in control.get("parts", []) or []:
        if p.get("name") != "statement":
            continue
        for sp in p.get("parts", []) or []:
            text = _prose_of(sp)
            if not text and not sp.get("prose"):
                continue
            kids.append({
                "id": sp.get("id", "").replace("_smt", ""),
                "display_id": _label(sp).strip(". ") or sp.get("id", ""),
                "title": "",
                "kind": "part",
                "statement": (sp.get("prose") or text or "").strip(),
                "guidance": "",
                "layer": None,
                "attributes": {},
                "children": [],
                "mappings": [],
                "source_ref": sp.get("id", ""),
                "source_handling": "verbatim",
            })
    return kids

import re as _re
_PARAM_TOKEN = _re.compile(r"\{\{\s*insert:\s*param,\s*([a-z0-9_.\-]+)\s*\}\}", _re.I)
# OSCAL cross-references like "[AU-02](#au-2)" or "[AU-2a.](#au-2_smt.a)" -> "AU-2a."
_XREF = _re.compile(r"\[([^\]]+)\]\(#[^)]*\)")
# any leftover bare anchors like "(#au-2)"
_BARE_ANCHOR = _re.compile(r"\s*\(#[a-z0-9_.\-]+\)", _re.I)

def _clean_xrefs(text: str) -> str:
    if not text:
        return text
    text = _XREF.sub(r"\1", text)          # keep the label, drop the link
    text = _BARE_ANCHOR.sub("", text)       # drop any orphan anchors
    return text

# Global map of param id -> readable label, built from the whole catalog.
_PARAM_LABELS: dict[str, str] = {}

def _collect_params(control: dict):
    for p in control.get("params", []) or []:
        pid = p.get("id", "")
        label = p.get("label", "")
        if not label:
            # fall back to select choices or guideline prose
            sel = p.get("select", {})
            if sel.get("choice"):
                label = " or ".join(sel["choice"])
        if pid and label:
            _PARAM_LABELS[pid] = label
    for sub in control.get("controls", []) or []:
        _collect_params(sub)

def _resolve_params(text: str) -> str:
    def repl(m):
        pid = m.group(1)
        label = _PARAM_LABELS.get(pid)
        if label:
            return f"[Assignment: organization-defined {label}]"
        return "[Assignment: organization-defined parameter]"
    return _PARAM_TOKEN.sub(repl, text or "")

def normalize_control(control: dict, family_id: str, is_enh=False) -> dict:
    layer = FAMILY_LAYER.get(family_id, "governance")
    node = {
        "id": control["id"],
        "display_id": _label(control) or control["id"].upper(),
        "title": control.get("title", ""),
        "kind": "enhancement" if is_enh else "control",
        "statement": _resolve_params(_statement(control)),
        "guidance": _resolve_params(_guidance(control)),
        "layer": layer,
        "attributes": {"family": family_id.upper()},
        "children": [],
        "mappings": [],
        "source_ref": control["id"],
        "source_handling": "verbatim",
    }
    for child in _statement_children(control):
        child["statement"] = _resolve_params(child["statement"])
        node["children"].append(child)
    for enh in control.get("controls", []) or []:
        node["children"].append(normalize_control(enh, family_id, is_enh=True))
    return node

def main(src_path: str, out_path: str):
    raw = Path(src_path).read_bytes()
    checksum = "sha256:" + hashlib.sha256(raw).hexdigest()
    cat = json.loads(raw)["catalog"]
    meta = cat.get("metadata", {})
    version = meta.get("version", "5.x")

    controls = []
    # First pass: collect every parameter label across the catalog.
    for group in cat.get("groups", []):
        for c in group.get("controls", []):
            _collect_params(c)
    # Second pass: normalize, resolving param tokens to readable text.
    for group in cat.get("groups", []):
        fam = group.get("id", "")
        for c in group.get("controls", []):
            controls.append(normalize_control(c, fam))

    # Final pass: resolve param tokens and clean OSCAL cross-references everywhere.
    def _resolve_tree(nodes):
        for n in nodes:
            n["statement"] = _clean_xrefs(_resolve_params(n.get("statement", "")))
            n["guidance"] = _clean_xrefs(_resolve_params(n.get("guidance", "")))
            _resolve_tree(n.get("children", []))
    _resolve_tree(controls)

    out = {
        "framework": {
            "id": "nist-800-53-r5",
            "name": "NIST SP 800-53 Rev. 5",
            "version": version,
            "publisher": "NIST",
            "source_handling": "verbatim",
            "source_url": "https://github.com/usnistgov/oscal-content",
            "license": "public-domain",
            "retrieved_at": datetime.date.today().isoformat(),
            "source_checksum": checksum,
        },
        "controls": controls,
    }
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(out, indent=2, ensure_ascii=False))
    # quick stats
    def count(nodes):
        n = len(nodes)
        for x in nodes:
            n += count(x["children"])
        return n
    print(f"families: {len(cat.get('groups', []))}")
    print(f"base controls: {len(controls)}")
    print(f"total nodes (incl. parts + enhancements): {count(controls)}")
    print(f"wrote {out_path}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
