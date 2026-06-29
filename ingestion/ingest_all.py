"""
Kyora IQ — wave-1 ingestion orchestrator.

Reproduces the entire normalized dataset from official sources in one command,
so the data's provenance is verifiable and the build is repeatable. Downloads
the NIST 800-53 OSCAL catalog, then runs every normalizer/builder, then builds
the crosswalk spine and validates it.

Usage:
  python ingestion/ingest_all.py            # full run (downloads NIST if missing)
  python ingestion/ingest_all.py --offline  # skip download, use existing raw file
"""
from __future__ import annotations
import json, subprocess, sys, urllib.request, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
NORM = ROOT / "data" / "normalized"
ING = ROOT / "ingestion"

NIST_OSCAL_URL = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
                  "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")
NIST_RAW = RAW / "nist_800_53_catalog.json"

ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
ATLAS_RAW = RAW / "atlas.yaml"

def run(label, args):
    print(f"\n=== {label} ===")
    r = subprocess.run([sys.executable, *args], cwd=ROOT)
    if r.returncode != 0:
        print(f"FAILED: {label}")
        sys.exit(r.returncode)

def download_nist():
    RAW.mkdir(parents=True, exist_ok=True)
    if NIST_RAW.exists():
        print(f"NIST source already present: {NIST_RAW.name} "
              f"({NIST_RAW.stat().st_size//1024} KB)")
        return
    print(f"Downloading NIST 800-53 OSCAL catalog...\n  {NIST_OSCAL_URL}")
    urllib.request.urlretrieve(NIST_OSCAL_URL, NIST_RAW)
    digest = hashlib.sha256(NIST_RAW.read_bytes()).hexdigest()
    print(f"  saved {NIST_RAW.stat().st_size//1024} KB  sha256:{digest[:16]}…")

def download_atlas():
    RAW.mkdir(parents=True, exist_ok=True)
    if ATLAS_RAW.exists():
        print(f"ATLAS source already present: {ATLAS_RAW.name} "
              f"({ATLAS_RAW.stat().st_size//1024} KB)")
        return
    print(f"Downloading MITRE ATLAS data...\n  {ATLAS_URL}")
    urllib.request.urlretrieve(ATLAS_URL, ATLAS_RAW)
    print(f"  saved {ATLAS_RAW.stat().st_size//1024} KB")

def main():
    offline = "--offline" in sys.argv
    NORM.mkdir(parents=True, exist_ok=True)

    if not offline:
        download_nist()
        download_atlas()
    elif not NIST_RAW.exists() or not ATLAS_RAW.exists():
        print("ERROR: --offline set but a raw source file is missing. Run once online first.")
        sys.exit(1)

    run("Normalize NIST 800-53 (OSCAL → schema)",
        [str(ING / "normalize_nist_oscal.py"), str(NIST_RAW), str(NORM / "nist-800-53-r5.json")])
    run("Build HIPAA Security Rule",
        [str(ING / "build_hipaa.py"), str(NORM / "hipaa-security-rule.json")])
    run("Build OWASP (LLM/API/Web) + NIST AI (RMF/600-1)",
        [str(ING / "build_owasp_nistai.py"), str(NORM)])
    run("Normalize MITRE ATLAS (official YAML → schema)",
        [str(ING / "normalize_atlas.py"), str(RAW / "atlas.yaml"), str(NORM / "mitre-atlas.json")])
    run("Build MITRE ATT&CK (curated subset)",
        [str(ING / "build_attack.py"), str(NORM / "mitre-attack.json")])
    run("Build wave-3 (SOC 2, ISO 42001, HITRUST, EU AI Act — own wording)",
        [str(ING / "build_wave3.py"), str(NORM)])
    run("Build crosswalk spine (layers, risks, mappings, index)",
        [str(ING / "build_crosswalk.py"), str(NORM)])

    # Final summary
    idx = json.loads((NORM / "_index.json").read_text())
    print("\n========== INGESTION COMPLETE ==========")
    print(f"frameworks:        {idx['counts']['frameworks']}")
    print(f"total control nodes:{idx['counts']['total_control_nodes']:>6}")
    print(f"canonical risks:   {idx['counts']['risks']}")
    print(f"mappings:          {idx['counts']['mappings']}")
    print("normalized files:")
    for f in sorted(NORM.glob("*.json")):
        print(f"  {f.name}")

if __name__ == "__main__":
    main()
