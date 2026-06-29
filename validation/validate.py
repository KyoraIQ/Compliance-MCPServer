"""
Kyora IQ — validation agent.

Treats data accuracy as a control. Runs a battery of checks against the
normalized dataset and, where possible, against the *current* official sources,
then writes a report. This is what lets Kyora IQ claim its data is trustworthy:
it can re-verify itself against the source of truth.

Checks performed:
  STRUCTURE   every normalized file matches the expected schema shape
  REFS        every risk control ref and every mapping endpoint resolves
  LAYERS      every control's layer is one of the defined layers
  ATTRIBUTION every framework records source_handling + license
  HIPAA       every implementation spec has a required/addressable flag
  SOURCE      (online) re-fetch the NIST OSCAL catalog and compare:
                - has the published version changed since retrieved_at?
                - does the source checksum still match?

Run:
  python validation/validate.py            # offline checks + online source check
  python validation/validate.py --offline  # skip the network source check
  python validation/validate.py --json      # machine-readable report to stdout

Exit code is non-zero if any ERROR-level finding is present (useful for CI).
"""
from __future__ import annotations
import json, sys, hashlib, urllib.request, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NORM = ROOT / "data" / "normalized"
RAW = ROOT / "data" / "raw"
NIST_OSCAL_URL = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
                  "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")
ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"

LAYER_IDS = {"input", "output", "model", "infrastructure", "agentic", "governance"}

class Report:
    def __init__(self):
        self.findings = []  # (level, check, message)
    def add(self, level, check, message):
        self.findings.append({"level": level, "check": check, "message": message})
    def ok(self, check, message):     self.add("OK", check, message)
    def warn(self, check, message):   self.add("WARN", check, message)
    def error(self, check, message):  self.add("ERROR", check, message)
    def has_errors(self):
        return any(f["level"] == "ERROR" for f in self.findings)

def load(name):
    return json.loads((NORM / name).read_text())

def iter_nodes(controls):
    for c in controls:
        yield c
        yield from iter_nodes(c.get("children", []))

def framework_files():
    return [f for f in sorted(NORM.glob("*.json")) if not f.name.startswith("_")]

# ---- checks -------------------------------------------------------------------
def check_structure(rep):
    required_fw = {"id", "name", "version", "publisher", "source_handling", "license"}
    required_ctrl = {"id", "display_id", "title", "kind", "statement", "layer", "children", "mappings"}
    for f in framework_files():
        try:
            d = json.loads(f.read_text())
        except Exception as e:
            rep.error("STRUCTURE", f"{f.name}: invalid JSON ({e})"); continue
        fw = d.get("framework", {})
        missing = required_fw - set(fw)
        if missing:
            rep.error("STRUCTURE", f"{f.name}: framework missing {sorted(missing)}")
        bad = 0
        for n in iter_nodes(d.get("controls", [])):
            if required_ctrl - set(n):
                bad += 1
        if bad:
            rep.error("STRUCTURE", f"{f.name}: {bad} control nodes missing required fields")
        else:
            rep.ok("STRUCTURE", f"{f.name}: schema shape OK ({sum(1 for _ in iter_nodes(d['controls']))} nodes)")

def build_ref_set():
    refs = set()
    for f in framework_files():
        d = json.loads(f.read_text())
        fwid = d["framework"]["id"]
        for n in iter_nodes(d["controls"]):
            refs.add(f"{fwid}:{n['id']}")
    return refs

def check_refs(rep):
    refs = build_ref_set()
    risks = load("_risks.json")["risks"]
    miss = 0
    for r in risks:
        for c in r.get("controls", []):
            if c not in refs:
                rep.error("REFS", f"risk '{r['id']}' -> unresolved control {c}"); miss += 1
    maps = load("_mappings.json")["mappings"]
    for m in maps:
        if m["from"] not in refs:
            rep.error("REFS", f"mapping from unresolved {m['from']}"); miss += 1
        if m["to"] not in refs:
            rep.error("REFS", f"mapping to unresolved {m['to']}"); miss += 1
    if not miss:
        rep.ok("REFS", f"all {len(risks)} risks and {len(maps)} mappings resolve")

def check_layers(rep):
    bad = 0
    for f in framework_files():
        d = json.loads(f.read_text())
        for n in iter_nodes(d["controls"]):
            lyr = n.get("layer")
            if lyr is not None and lyr not in LAYER_IDS:
                rep.error("LAYERS", f"{d['framework']['id']}:{n['id']} has invalid layer '{lyr}'"); bad += 1
    if not bad:
        rep.ok("LAYERS", "all control layers are valid")

def check_attribution(rep):
    valid_handling = {"verbatim", "paraphrased", "own-wording"}
    for f in framework_files():
        fw = json.loads(f.read_text())["framework"]
        if fw.get("source_handling") not in valid_handling:
            rep.error("ATTRIBUTION", f"{fw['id']}: bad source_handling '{fw.get('source_handling')}'")
        elif not fw.get("license") or not fw.get("source_url"):
            rep.warn("ATTRIBUTION", f"{fw['id']}: missing license or source_url")
        else:
            rep.ok("ATTRIBUTION", f"{fw['id']}: {fw['source_handling']} / {fw['license']}")

def check_hipaa(rep):
    p = NORM / "hipaa-security-rule.json"
    if not p.exists():
        rep.warn("HIPAA", "hipaa-security-rule.json not present"); return
    d = json.loads(p.read_text())
    missing = 0
    for std in d["controls"]:
        for spec in std.get("children", []):
            if spec.get("attributes", {}).get("requirement") not in {"required", "addressable"}:
                rep.error("HIPAA", f"spec {spec['display_id']} missing required/addressable flag"); missing += 1
    if not missing:
        rep.ok("HIPAA", "every implementation spec carries a required/addressable flag")

def check_source_nist(rep, offline):
    p = NORM / "nist-800-53-r5.json"
    if not p.exists():
        rep.warn("SOURCE", "nist-800-53-r5.json not present"); return
    fw = json.loads(p.read_text())["framework"]
    recorded = fw.get("source_checksum", "")
    recorded_version = fw.get("version", "")
    if offline:
        rep.warn("SOURCE", "offline: skipped live NIST source comparison")
        return
    try:
        with urllib.request.urlopen(NIST_OSCAL_URL, timeout=60) as r:
            raw = r.read()
    except Exception as e:
        rep.warn("SOURCE", f"could not fetch current NIST source ({e}); skipping drift check")
        return
    current = "sha256:" + hashlib.sha256(raw).hexdigest()
    try:
        cur_version = json.loads(raw)["catalog"]["metadata"].get("version", "?")
    except Exception:
        cur_version = "?"
    if current == recorded:
        rep.ok("SOURCE", f"NIST source unchanged since ingestion (version {recorded_version})")
    else:
        if cur_version != recorded_version:
            rep.error("SOURCE",
                      f"NIST 800-53 has a NEW published version: ingested {recorded_version}, "
                      f"current {cur_version}. Re-run ingestion to update.")
        else:
            rep.warn("SOURCE",
                     f"NIST source bytes changed but version still {cur_version}. "
                     f"Likely a non-substantive republish; consider re-ingesting to refresh checksum.")

def check_source_atlas(rep, offline):
    p = NORM / "mitre-atlas.json"
    if not p.exists():
        return  # ATLAS not ingested (wave 2); nothing to check
    fw = json.loads(p.read_text())["framework"]
    recorded = fw.get("source_checksum", "")
    if offline:
        rep.warn("SOURCE", "offline: skipped live ATLAS source comparison")
        return
    try:
        with urllib.request.urlopen(ATLAS_URL, timeout=60) as r:
            raw = r.read()
    except Exception as e:
        rep.warn("SOURCE", f"could not fetch current ATLAS source ({e}); skipping drift check")
        return
    current = "sha256:" + hashlib.sha256(raw).hexdigest()
    if current == recorded:
        rep.ok("SOURCE", f"MITRE ATLAS source unchanged since ingestion (version {fw.get('version')})")
    else:
        rep.warn("SOURCE",
                 f"MITRE ATLAS source has changed since ingestion (recorded version {fw.get('version')}). "
                 f"Re-run ingestion to refresh.")

def check_bucket3(rep):
    """Guard the IP policy: licensed-source frameworks must be flagged own-wording."""
    bucket3 = {"soc2-tsc", "iso-42001", "eu-ai-act"}
    for f in framework_files():
        fw = json.loads(f.read_text())["framework"]
        if fw["id"] in bucket3:
            if fw.get("source_handling") != "own-wording":
                rep.error("BUCKET3",
                          f"{fw['id']}: licensed source must be 'own-wording', got '{fw.get('source_handling')}'")
            else:
                rep.ok("BUCKET3", f"{fw['id']}: correctly flagged own-wording (licensed source)")

# ---- runner -------------------------------------------------------------------
def main():
    offline = "--offline" in sys.argv
    as_json = "--json" in sys.argv
    rep = Report()
    check_structure(rep)
    check_refs(rep)
    check_layers(rep)
    check_attribution(rep)
    check_hipaa(rep)
    check_bucket3(rep)
    check_source_nist(rep, offline)
    check_source_atlas(rep, offline)

    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "ok": sum(1 for f in rep.findings if f["level"] == "OK"),
            "warn": sum(1 for f in rep.findings if f["level"] == "WARN"),
            "error": sum(1 for f in rep.findings if f["level"] == "ERROR"),
        },
        "findings": rep.findings,
    }
    (ROOT / "validation" / "last_report.json").write_text(json.dumps(report, indent=2))

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        icon = {"OK": "  ok ", "WARN": " warn", "ERROR": "ERROR"}
        print("Kyora IQ validation report —", report["generated_at"])
        print("-" * 60)
        for f in rep.findings:
            print(f"[{icon[f['level']]}] {f['check']:<12} {f['message']}")
        print("-" * 60)
        s = report["summary"]
        print(f"OK: {s['ok']}   WARN: {s['warn']}   ERROR: {s['error']}")
        print("PASS" if not rep.has_errors() else "FAIL (errors present)")

    sys.exit(1 if rep.has_errors() else 0)

if __name__ == "__main__":
    main()
