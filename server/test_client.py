"""
Smoke test for the Kyora IQ MCP server. Starts nothing itself — assumes the
server is already running on http://127.0.0.1:8000/mcp — connects as a real MCP
client, lists tools, and calls each one.

Run (with the server running in another terminal):
  python server/test_client.py
"""
import asyncio, json
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = "http://127.0.0.1:8000/mcp"

def show(title, result):
    print(f"\n--- {title} ---")
    for block in result.content:
        if block.type == "text":
            try:
                data = json.loads(block.text)
                print(json.dumps(data, indent=2)[:700])
            except Exception:
                print(block.text[:700])

async def main():
    async with streamablehttp_client(URL) as (read, write, _):
        async with ClientSession(read, write) as s:
            await s.initialize()
            tools = await s.list_tools()
            print("TOOLS:", [t.name for t in tools.tools])

            show("list_frameworks", await s.call_tool("list_frameworks", {}))
            show("search_controls('audit logging')",
                 await s.call_tool("search_controls", {"query": "audit logging", "limit": 5}))
            show("get_control(nist-800-53-r5, ac-2)",
                 await s.call_tool("get_control", {"framework": "nist-800-53-r5", "control_id": "ac-2"}))
            show("get_mappings(hipaa, 164.312(a)(1))",
                 await s.call_tool("get_mappings", {"framework": "hipaa-security-rule", "control_id": "164.312(a)(1)"}))
            show("list_risks(layer=input)",
                 await s.call_tool("list_risks", {"layer": "input"}))
            show("get_risk(prompt-injection)",
                 await s.call_tool("get_risk", {"risk_id": "prompt-injection"}))

if __name__ == "__main__":
    asyncio.run(main())
