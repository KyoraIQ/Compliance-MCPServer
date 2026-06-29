# Connect your AI assistant to Kyora IQ

Your instructor is hosting the Kyora IQ compliance MCP server. You don't run
anything — you just point your assistant at it.

## What you need

- **Server URL:** `https://<your-instructor-fills-in>.onrender.com/mcp`
- **Access token:** `<your-instructor-fills-in>`

Keep the token private to the class.

## Option A — Claude (remote connector)

1. Open Claude's settings and find **Connectors** (or "Custom connectors").
2. Add a connector with the **Server URL** above.
3. When asked for authentication, provide the **access token** as a bearer token.
4. Start a chat and ask something like *"Using Kyora IQ, what does NIST AC-2
   require?"* — Claude will call the server's tools.

> Exact menu names and which plans support custom remote connectors change over
> time. If you don't see Connectors, check Claude's current docs.

## Option B — Your own code (Python)

```python
import asyncio
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = "https://<instructor>.onrender.com/mcp"
HEADERS = {"Authorization": "Bearer <token>"}

async def main():
    async with streamablehttp_client(URL, headers=HEADERS) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            print([t.name for t in tools.tools])
            res = await s.call_tool("search_controls", {"query": "audit logging"})
            print(res.content[0].text)

asyncio.run(main())
```

(`pip install mcp` first.)

## Option C — A local assistant that only does stdio

Some local tools speak the older stdio transport. Bridge to the remote server
with `mcp-remote`:

```bash
npx mcp-remote https://<instructor>.onrender.com/mcp \
  --header "Authorization: Bearer <token>"
```

Then point your assistant at the local bridge it creates.

## The tools you can use

- `list_frameworks` — what frameworks are available
- `search_controls` — find controls by keyword
- `get_control` — full text of one control, with nested parts
- `get_mappings` — how a control maps across frameworks
- `list_risks` / `get_risk` — risks and the controls that address them

## Troubleshooting

- **401 unauthorized** → token missing or wrong.
- **429 too many requests** → you hit the rate limit; wait a minute.
- **Can't connect** → confirm the URL ends in `/mcp` and starts with `https://`.
