"""
Kyora IQ — Security Gateway (Phase 3, step 1).

Wraps the compliance MCP server with the minimum controls needed to expose it
safely to a classroom or the public:

  - binds to KYORA_HOST/KYORA_PORT (set 0.0.0.0 to accept outside connections)
  - requires a bearer token on every MCP request (KYORA_TOKEN)
  - per-token rate limiting (KYORA_RATE_PER_MIN)
  - a /health endpoint for the host's uptime checks (no auth)

Everything is driven by environment variables so configuration is one .env file.
Run:
  python server/gateway.py
"""
from __future__ import annotations
import os
import time
from collections import defaultdict, deque
from pathlib import Path

# Load .env (simple parser; no dependency). Real env vars take precedence.
_envfile = Path(__file__).resolve().parent.parent / ".env"
if _envfile.exists():
    for _line in _envfile.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from server import mcp, HOST, PORT  # reuse the configured FastMCP instance

# Many hosts (Render, Railway, Heroku) inject PORT; honor it over KYORA_PORT.
PORT = int(os.environ.get("PORT", PORT))

# ---- config -------------------------------------------------------------------
TOKEN = os.environ.get("KYORA_TOKEN", "")            # empty = auth disabled (dev)
RATE_PER_MIN = int(os.environ.get("KYORA_RATE_PER_MIN", "60"))
PUBLIC_PATHS = {"/health"}

# ---- rate limiter (in-memory, per token; fine for a classroom) ----------------
_hits: dict[str, deque] = defaultdict(deque)

def _rate_ok(key: str) -> bool:
    now = time.time()
    window = _hits[key]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= RATE_PER_MIN:
        return False
    window.append(now)
    return True

# ---- middleware ---------------------------------------------------------------
class Gateway(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # auth
        if TOKEN:
            auth = request.headers.get("authorization", "")
            supplied = auth[7:] if auth.lower().startswith("bearer ") else ""
            if supplied != TOKEN:
                return JSONResponse({"error": "unauthorized"}, status_code=401)

        # rate limit (per token, or per client host if no token)
        key = TOKEN or (request.client.host if request.client else "anon")
        if not _rate_ok(key):
            return JSONResponse({"error": "rate limit exceeded"}, status_code=429)

        return await call_next(request)

# ---- health -------------------------------------------------------------------
async def health(_request):
    return JSONResponse({"status": "ok", "service": "kyora-iq-mcp"})

# ---- app ----------------------------------------------------------------------
def build_app():
    mcp_app = mcp.streamable_http_app()  # the MCP ASGI app at /mcp
    app = Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            *mcp_app.routes,
        ],
        lifespan=getattr(mcp_app, "lifespan", None) or getattr(mcp_app.router, "lifespan_context", None),
    )
    app.add_middleware(Gateway)
    return app

app = build_app()

if __name__ == "__main__":
    import uvicorn
    if not TOKEN:
        print("WARNING: KYORA_TOKEN is empty — auth is DISABLED (development mode).")
    if HOST == "127.0.0.1":
        print("NOTE: bound to 127.0.0.1 (local only). Set KYORA_HOST=0.0.0.0 to accept outside connections.")
    print(f"Kyora IQ gateway on http://{HOST}:{PORT}  (MCP at /mcp, health at /health)")
    uvicorn.run(app, host=HOST, port=PORT, log_level=os.environ.get("KYORA_LOG", "info"))
