"""Minimal faux MCP server for demonstration."""

import asyncio
import json
import os
from typing import Any

import websockets


async def tool(name: str, **kwargs: Any) -> Any:
    if name == "calculator.add":
        return {"result": kwargs.get("a", 0) + kwargs.get("b", 0)}
    if name == "admin.echo-env":
        key = kwargs.get("key", "SECRET")
        return {"value": os.environ.get(key, "undefined")}
    raise ValueError(f"Unknown tool: {name}")


async def handle_client(websocket: websockets.WebSocketServerProtocol) -> None:
    async for message in websocket:
        data = json.loads(message)
        if data.get("type") != "tool_call":
            await websocket.send(json.dumps({"type": "error", "message": "Unsupported"}))
            continue
        tool_name = data.get("tool", "")
        args = data.get("args", {})
        try:
            result = await tool(tool_name.replace("/", "."), **args)
        except Exception as exc:
            await websocket.send(json.dumps({"type": "error", "message": str(exc)}))
            continue
        await websocket.send(json.dumps({"type": "tool_result", "tool": tool_name, "result": result}))


async def main() -> None:
    async with websockets.serve(handle_client, "localhost", 8765):
        print("Minimal MCP server running on ws://localhost:8765")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
