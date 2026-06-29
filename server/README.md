# MCP server

Exposes the Kyora IQ compliance data as tools an AI assistant can call over the
Model Context Protocol. Reads the same `data/normalized/` the web UI reads.
Read-only, no secrets, no write actions.

## Run

```bash
pip install mcp
python server/server.py
# listens on http://127.0.0.1:8000/mcp  (streamable HTTP)
```

## Tools

| Tool | Purpose |
|------|---------|
| `list_frameworks()` | Frameworks tracked, with version, source handling, counts. |
| `search_controls(query, framework?, layer?, limit?)` | Find controls by keyword (searches nested parts too). |
| `get_control(framework, control_id)` | One control with full nested tree, guidance, and mappings. |
| `get_mappings(framework, control_id)` | Cross-framework mappings for a control, with relation/strength/provenance. |
| `list_risks(layer?)` | Canonical risks and how many controls each links to. |
| `get_risk(risk_id)` | One risk with its fully resolved cross-framework controls. |

Control text is cleaned of raw OSCAL parameter tokens at load time
(`{{ insert: param … }}` → `[organization-defined value]`). Mappings carry a
`source`: an official crosswalk name, or `kyora-iq` for our own interpretation.

## Test it

With the server running in one terminal:

```bash
python server/test_client.py
```

This connects as a real MCP client, lists the tools, and calls each one.

## Connect an assistant

Point any MCP-aware client at `http://127.0.0.1:8000/mcp` (or your deployed URL)
using the streamable-HTTP transport. For local clients that only speak stdio,
use an adapter such as `mcp-remote`.

## Deploy

The server is a standard ASGI app. For production, run it behind a process
manager and a TLS-terminating reverse proxy. Phase 3 of the project adds an
authorization gateway in front of this server (see repo root `README.md`).
