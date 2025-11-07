"""Sidecar proxy and CLI entry points."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import websockets
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

from .attestation import hash_payload
from .exceptions import PolicyDenied, Unauthorized
from .guard import Guard
from .policy import load_policy
from .types import Metrics


class ProxyServer:
    def __init__(self, guard: Guard, target_url: str) -> None:
        self.guard = guard
        self.target_url = target_url
        self.metrics = Metrics()

    async def handle(self, websocket: WebSocket) -> None:
        await websocket.accept()
        try:
            async with websockets.connect(self.target_url) as upstream:
                client_task = asyncio.create_task(self._client_to_upstream(websocket, upstream))
                server_task = asyncio.create_task(self._upstream_to_client(websocket, upstream))
                done, pending = await asyncio.wait(
                    {client_task, server_task},
                    return_when=asyncio.FIRST_EXCEPTION,
                )
                for task in pending:
                    task.cancel()
                for task in done:
                    exc = task.exception()
                    if exc:
                        raise exc
        except WebSocketDisconnect:
            return
        except Exception:
            self.metrics.errors += 1
            raise

    async def _client_to_upstream(self, websocket: WebSocket, upstream: websockets.WebSocketClientProtocol) -> None:
        while True:
            message = await websocket.receive_text()
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                await upstream.send(message)
                continue
            if data.get("type") == "tool_call":
                identity = data.get("identity", "anonymous")
                tool = data.get("tool", "")
                prompt = data.get("prompt")
                resources = data.get("resources", [])
                try:
                    await self.guard.check_tool(
                        identity,
                        tool,
                        prompt_text=prompt,
                        resources=resources,
                    )
                except PolicyDenied as exc:
                    self.metrics.denied += 1
                    await websocket.send_json(
                        {
                            "type": "error",
                            "error": "PolicyDenied",
                            "message": str(exc),
                            "details": exc.details if hasattr(exc, "details") else None,
                        }
                    )
                    continue
                except Unauthorized as exc:
                    self.metrics.denied += 1
                    await websocket.send_json(
                        {
                            "type": "error",
                            "error": "Unauthorized",
                            "message": str(exc),
                        }
                    )
                    continue
                self.metrics.allowed += 1
                request_hash = None
                if self.guard.policy.attestation.enabled:
                    request_hash = hash_payload(data, self.guard.policy.attestation.alg)
                self.guard.audit.log(
                    identity=identity,
                    tool=tool,
                    action="tool",
                    decision="allow",
                    findings=[],
                    request_hash=request_hash,
                    response_hash=None,
                )
            await upstream.send(message)

    async def _upstream_to_client(self, websocket: WebSocket, upstream: websockets.WebSocketClientProtocol) -> None:
        while True:
            message = await upstream.recv()
            if isinstance(message, bytes):
                await websocket.send_bytes(message)
            else:
                await websocket.send_text(message)


def create_app(proxy: ProxyServer) -> FastAPI:
    app = FastAPI()

    @app.get("/healthz")
    async def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/metrics")
    async def metrics() -> dict[str, Any]:
        return proxy.metrics.to_dict()

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket) -> None:
        await proxy.handle(ws)

    return app


async def run_proxy(args: argparse.Namespace) -> None:
    policy = load_policy(args.policy)
    guard = Guard(policy)
    proxy = ProxyServer(guard, args.target)
    app = create_app(proxy)
    config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def run_check(args: argparse.Namespace) -> None:
    policy = load_policy(args.policy)
    guard = Guard(policy)
    identity = args.identity or "anonymous"
    resources = [args.resource] if args.resource else None
    try:
        decision = await guard.check_tool(
            identity,
            args.tool,
            prompt_text=args.prompt,
            resources=resources,
        )
    except PolicyDenied as exc:
        print("DENY:", exc)
        return
    print("ALLOW", decision.quota_remaining)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcpguard", description="MCP Guard CLI")
    sub = parser.add_subparsers(dest="command")

    proxy_cmd = sub.add_parser("proxy", help="Run guard proxy")
    proxy_cmd.add_argument("--policy", required=True)
    proxy_cmd.add_argument("--target", required=True)
    proxy_cmd.add_argument("--host", default="0.0.0.0")
    proxy_cmd.add_argument("--port", type=int, default=8787)

    check_cmd = sub.add_parser("check", help="Evaluate a prompt against policy")
    check_cmd.add_argument("--policy", required=True)
    check_cmd.add_argument("--tool", required=True)
    check_cmd.add_argument("--prompt", default="")
    check_cmd.add_argument("--identity", default="anonymous")
    check_cmd.add_argument("--resource")

    return parser


def cli_main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "proxy":
        asyncio.run(run_proxy(args))
    elif args.command == "check":
        asyncio.run(run_check(args))
    else:
        parser.print_help()
