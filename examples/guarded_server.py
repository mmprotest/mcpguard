"""Example MCP server guarded by mcpguard."""

import asyncio
import json
from typing import Any, Callable

import websockets

from mcpguard.guard import Guard
from mcpguard.policy import load_policy

policy = load_policy("examples/policy.yaml")
guard = Guard(policy)


@guard.wrap_tool(tool_name="calculator.add")
async def calculator_add(a: int, b: int) -> dict[str, int]:
    return {"result": a + b}


@guard.wrap_tool(tool_name="admin.echo-env")
async def admin_echo_env(key: str = "SECRET") -> dict[str, str]:
    import os

    return {"value": os.environ.get(key, "undefined")}


tools: dict[str, Callable[..., Any]] = {
    "calculator.add": calculator_add,
    "admin.echo-env": admin_echo_env,
}


async def handle_client(websocket: websockets.WebSocketServerProtocol) -> None:
    async for message in websocket:
        data = json.loads(message)
        if data.get("type") != "tool_call":
            await websocket.send(json.dumps({"type": "error", "message": "Unsupported"}))
            continue
        tool_name = data.get("tool", "")
        args = data.get("args", {})
        tool_fn = tools.get(tool_name.replace("/", ".")) or tools.get(tool_name)
        if tool_fn is None:
            await websocket.send(json.dumps({"type": "error", "message": "Unknown tool"}))
            continue
        try:
            result = await tool_fn(**args, _guard_context={"identity": data.get("identity", "anonymous"), "prompt": data.get("prompt"), "resources": data.get("resources", [])})
        except Exception as exc:
            await websocket.send(json.dumps({"type": "error", "message": str(exc)}))
            continue
        await websocket.send(json.dumps({"type": "tool_result", "tool": tool_name, "result": result}))


async def main() -> None:
    async with websockets.serve(handle_client, "localhost", 8766):
        print("Guarded MCP server running on ws://localhost:8766 (policy enforced)")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
