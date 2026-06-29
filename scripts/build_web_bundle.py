"""
Rebuild the web data bundle (web/kyora-data.json) from data/normalized/.
Run after any change to the normalized data so the web UI picks it up.

  python scripts/build_web_bundle.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NORM = ROOT / "data" / "normalized"
OUT = ROOT / "web" / "kyora-data.json"

def main():
    bundle = {
        "index": json.loads((NORM / "_index.json").read_text()),
        "layers": json.loads((NORM / "_layers.json").read_text())["layers"],
        "risks": json.loads((NORM / "_risks.json").read_text())["risks"],
        "mappings": json.loads((NORM / "_mappings.json").read_text())["mappings"],
        "frameworks": {},
    }
    for f in sorted(NORM.glob("*.json")):
        if f.name.startswith("_"):
            continue
        d = json.loads(f.read_text())
        bundle["frameworks"][d["framework"]["id"]] = d
    OUT.write_text(json.dumps(bundle, ensure_ascii=False))
    kb = OUT.stat().st_size // 1024
    print(f"wrote {OUT} ({kb} KB, {len(bundle['frameworks'])} frameworks)")

if __name__ == "__main__":
    main()
