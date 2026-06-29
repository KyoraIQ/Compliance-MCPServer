# Validation agent

Treats data accuracy as a control. Re-verifies the normalized dataset for
internal integrity and, where possible, against the *current* official sources —
so Kyora IQ can prove its data is trustworthy rather than just assert it.

## Run

```bash
python validation/validate.py            # all checks, incl. live NIST source drift
python validation/validate.py --offline  # integrity checks only (no network)
python validation/validate.py --json     # machine-readable report to stdout
```

Exit code is non-zero if any ERROR finding is present, so it can gate CI.
The latest run is written to `validation/last_report.json`.

## What it checks

| Check | What it verifies |
|-------|------------------|
| STRUCTURE | Every normalized file matches the expected schema shape. |
| REFS | Every risk control reference and mapping endpoint resolves to a real control. |
| LAYERS | Every control's layer is one of the six defined layers. |
| ATTRIBUTION | Every framework records a valid source_handling, license, and source URL. |
| HIPAA | Every implementation specification carries a Required/Addressable flag. |
| SOURCE | (online) Re-fetches the NIST OSCAL catalog and compares version + checksum against what was ingested; flags a new published version as an ERROR. |

## Why this matters

Because Kyora IQ feeds AI assistants, the accuracy of its content is a trust
boundary: wrong data makes every assistant relying on it confidently wrong. The
validation agent is the control that defends that boundary. The `SOURCE` check in
particular detects when an upstream publication has changed since ingestion, so
stale data is caught automatically instead of silently served.

Future source checks (per framework) plug in alongside the NIST one as those
frameworks gain machine-readable sources or stable change signals.
