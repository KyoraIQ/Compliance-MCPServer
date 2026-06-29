# Web interface

Search-primary compliance control reference. Static single-page app — no build
step, no framework runtime. Reads `kyora-data.json` (produced by ingestion).

## Run locally

```bash
# from repo root, after running ingestion at least once:
cd web
python3 -m http.server 8000
# open http://localhost:8000
```

`kyora-data.json` is the bundled output of `../data/normalized/`. Regenerate it
whenever the data changes:

```bash
python ingestion/ingest_all.py
python - <<'PY'
import json; from pathlib import Path
norm=Path('data/normalized')
b={'index':json.loads((norm/'_index.json').read_text()),
   'layers':json.loads((norm/'_layers.json').read_text())['layers'],
   'risks':json.loads((norm/'_risks.json').read_text())['risks'],
   'mappings':json.loads((norm/'_mappings.json').read_text())['mappings'],
   'frameworks':{}}
for f in sorted(norm.glob('*.json')):
    if f.name.startswith('_'): continue
    d=json.loads(f.read_text()); b['frameworks'][d['framework']['id']]=d
Path('web/kyora-data.json').write_text(json.dumps(b,ensure_ascii=False))
print('rebuilt web/kyora-data.json')
PY
```

## Deploy to Vercel

The `web/` folder is a static site. Point Vercel at it:

1. Push the repo to GitHub.
2. In Vercel, import the repo and set the **root directory** to `web`.
3. Framework preset: **Other** (no build command, output dir is the folder itself).
4. Deploy. `vercel.json` handles clean URLs and caching for the data bundle.

## Features

- Search across all controls including nested parts and enhancements.
- Filter by layer (Input/Output/Model/Infrastructure/Agentic/Governance) or framework.
- Inline drop-down expansion showing full control text, guidance, implementation
  specifications with Required/Addressable flags (HIPAA), enhancements (NIST), and
  cross-framework mappings with relation, strength, and provenance.
- Source-handling note on every control (verbatim / paraphrased / own wording).
