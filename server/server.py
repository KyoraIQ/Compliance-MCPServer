"""
Kyora IQ — MCP Compliance Control Reference server.

Exposes the normalized compliance data (the same data the web UI reads) as tools
an AI assistant can call over the Model Context Protocol. Read-only; no secrets;
no write actions. This is the connector an assistant uses to get authoritative,
cited control text instead of guessing.

Tools:
  list_frameworks()                       -> the frameworks tracked, with counts
  search_controls(query, framework?, layer?, limit?)
                                          -> matching controls (incl. nested text)
  get_control(framework, control_id)      -> one control with full tree + guidance
  get_mappings(framework, control_id)     -> cross-framework mappings for a control
  list_risks(layer?)                      -> canonical risks and the controls they link to
  get_risk(risk_id)                       -> one risk with resolved controls

Run (streamable HTTP, web-accessible):
  python server/server.py
  # listens on http://127.0.0.1:8000/mcp
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# Config from environment (see .env.example). Defaults are safe for local dev.
HOST = os.environ.get("KYORA_HOST", "127.0.0.1")
PORT = int(os.environ.get("KYORA_PORT", "8000"))

NORM = Path(__file__).resolve().parent.parent / "data" / "normalized"

# ---- load data once at startup ------------------------------------------------
def _load(name: str) -> dict:
    return json.loads((NORM / name).read_text())

import re as _re
_PARAM = _re.compile(r"\{\{\s*insert:\s*param,\s*([a-z0-9_.\-]+)\s*\}\}", _re.I)

def _clean_text(s: str) -> str:
    """Replace raw OSCAL parameter tokens with a readable placeholder."""
    if not s:
        return s
    return _PARAM.sub("[organization-defined value]", s)

def _clean_node(n: dict) -> dict:
    n["statement"] = _clean_text(n.get("statement", ""))
    n["guidance"] = _clean_text(n.get("guidance", ""))
    for ch in n.get("children", []):
        _clean_node(ch)
    return n

FRAMEWORKS: dict[str, dict] = {}
for f in sorted(NORM.glob("*.json")):
    if f.name.startswith("_"):
        continue
    d = json.loads(f.read_text())
    for _c in d["controls"]:
        _clean_node(_c)
    FRAMEWORKS[d["framework"]["id"]] = d

INDEX = _load("_index.json")
RISKS = _load("_risks.json")["risks"]
MAPPINGS = _load("_mappings.json")["mappings"]
ATTRIBUTION = (
    "Framework content: NIST and HIPAA are public-domain U.S. Government sources. "
    "OWASP content © OWASP Foundation (CC BY-SA 4.0). Mappings marked 'kyora-iq' are "
    "Kyora IQ's interpretation. This is a reference, not a certification or legal advice."
)

# ---- helpers ------------------------------------------------------------------
def _iter_controls(fwid: str):
    for c in FRAMEWORKS[fwid]["controls"]:
        yield c

def _find_control(fwid: str, control_id: str) -> Optional[dict]:
    raw = control_id.strip().lower()
    cid = raw.replace(" ", "").replace("§", "")
    def norm(s: str) -> str:
        return (s or "").lower().replace(" ", "").replace("§", "")
    def walk(nodes):
        for n in nodes:
            attrs = n.get("attributes", {}) or {}
            candidates = {norm(n["id"]), norm(n["display_id"]), norm(attrs.get("section", ""))}
            if cid in candidates:
                return n
            hit = walk(n.get("children", []))
            if hit:
                return hit
        return None
    if fwid not in FRAMEWORKS:
        return None
    return walk(FRAMEWORKS[fwid]["controls"])

def _control_haystack(c: dict) -> str:
    parts = [c.get("display_id", ""), c.get("title", ""), c.get("statement", ""), c.get("guidance", "")]
    for ch in c.get("children", []):
        parts += [ch.get("display_id", ""), ch.get("title", ""), ch.get("statement", "")]
    return " ".join(parts).lower()

def _mappings_for(ref: str) -> list[dict]:
    out = []
    for m in MAPPINGS:
        if m["from"] == ref:
            out.append({"control": m["to_display"], "title": m["to_title"],
                        "framework": m["to"].split(":")[0], "relation": m["relation"],
                        "strength": m["strength"], "source": m["source"], "rationale": m["rationale"]})
        elif m["to"] == ref:
            out.append({"control": m["from_display"], "title": m["from_title"],
                        "framework": m["from"].split(":")[0], "relation": m["relation"],
                        "strength": m["strength"], "source": m["source"], "rationale": m["rationale"]})
    return out

def _summary(c: dict) -> dict:
    return {"id": c["id"], "display_id": c["display_id"], "title": c["title"],
            "layer": c.get("layer"), "kind": c["kind"],
            "statement_preview": (c.get("statement", "")[:180]).strip()}

# ---- server -------------------------------------------------------------------
mcp = FastMCP(
    name="kyora-iq-compliance-reference",
    instructions=(
        "Authoritative, read-only reference for security, privacy, and AI-governance "
        "controls across multiple frameworks (NIST 800-53, HIPAA, OWASP LLM/API/Web, "
        "NIST AI RMF, NIST AI 600-1, and more). Use search_controls to find controls by "
        "keyword, get_control for the full text and nested structure of one control, and "
        "get_mappings to see how a control relates to other frameworks. Always prefer "
        "citing the returned display_id and framework over recalling from memory. " + ATTRIBUTION
    ),
    host=HOST,
    port=PORT,
)

@mcp.tool()
def list_frameworks() -> dict[str, Any]:
    """List every framework tracked, with version, source handling, and control counts."""
    return {"frameworks": INDEX["frameworks"], "counts": INDEX["counts"],
            "generated_at": INDEX["generated_at"], "attribution": ATTRIBUTION}

@mcp.tool()
def search_controls(query: str, framework: str = "", layer: str = "", limit: int = 10) -> dict[str, Any]:
    """Search controls across all frameworks by keyword (searches nested parts too).

    Args:
        query: Keywords, e.g. 'audit logging' or 'prompt injection' or 'AC-2'.
        framework: Optional framework id to restrict to (see list_frameworks).
        layer: Optional layer: input, output, model, infrastructure, agentic, governance.
        limit: Max results (1-50). Defaults to 10.
    """
    q = query.lower().strip()
    if not q:
        return {"ok": False, "error": "query must not be empty"}
    limit = max(1, min(int(limit), 50))
    results = []
    for fwid, data in FRAMEWORKS.items():
        if framework and fwid != framework:
            continue
        for c in data["controls"]:
            if layer and c.get("layer") != layer:
                continue
            if q in _control_haystack(c):
                r = _summary(c)
                r["framework"] = fwid
                r["framework_name"] = data["framework"]["name"]
                results.append(r)
    return {"ok": True, "query": query, "match_count": len(results), "results": results[:limit]}

@mcp.tool()
def get_control(framework: str, control_id: str) -> dict[str, Any]:
    """Retrieve one control with its full nested structure, guidance, and mappings.

    Args:
        framework: Framework id, e.g. 'nist-800-53-r5' or 'hipaa-security-rule'.
        control_id: Control id or display id, e.g. 'ac-2', 'AC-2', or '164.312(a)(1)'.
    """
    if framework not in FRAMEWORKS:
        return {"ok": False, "error": f"unknown framework '{framework}'",
                "available": list(FRAMEWORKS.keys())}
    c = _find_control(framework, control_id)
    if not c:
        return {"ok": False, "error": f"no control '{control_id}' in {framework}"}
    ref = f"{framework}:{c['id']}"
    return {"ok": True, "framework": framework,
            "framework_name": FRAMEWORKS[framework]["framework"]["name"],
            "source_handling": FRAMEWORKS[framework]["framework"]["source_handling"],
            "control": c, "mappings": _mappings_for(ref), "attribution": ATTRIBUTION}

@mcp.tool()
def get_mappings(framework: str, control_id: str) -> dict[str, Any]:
    """Get the cross-framework mappings for one control (how it relates elsewhere).

    Args:
        framework: Framework id.
        control_id: Control id or display id.
    """
    c = _find_control(framework, control_id)
    if not c:
        return {"ok": False, "error": f"no control '{control_id}' in {framework}"}
    ref = f"{framework}:{c['id']}"
    maps = _mappings_for(ref)
    return {"ok": True, "control": c["display_id"], "framework": framework,
            "mapping_count": len(maps), "mappings": maps,
            "note": "Mappings with source 'kyora-iq' are Kyora IQ's interpretation, not official crosswalks."}

@mcp.tool()
def list_risks(layer: str = "") -> dict[str, Any]:
    """List the canonical risks and the controls each links to across frameworks.

    Args:
        layer: Optional layer filter (input/output/model/infrastructure/agentic/governance).
    """
    rs = [r for r in RISKS if not layer or r.get("layer") == layer]
    return {"ok": True, "risk_count": len(rs),
            "risks": [{"id": r["id"], "title": r["title"], "layer": r["layer"],
                       "summary": r["summary"],
                       "control_count": len(r.get("controls_resolved", []))} for r in rs]}

@mcp.tool()
def get_risk(risk_id: str) -> dict[str, Any]:
    """Get one canonical risk with its fully resolved cross-framework controls.

    Args:
        risk_id: e.g. 'prompt-injection', 'broken-access-control'.
    """
    for r in RISKS:
        if r["id"] == risk_id.strip().lower():
            return {"ok": True, "risk": r, "attribution": ATTRIBUTION}
    return {"ok": False, "error": f"no risk '{risk_id}'",
            "available": [r["id"] for r in RISKS]}

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
