"""Core guard middleware."""

from __future__ import annotations

import asyncio
from functools import wraps
from typing import Any, Awaitable, Callable, Iterable
from dataclasses import asdict

from .acl import ResourceACL
from .attestation import hash_payload
from .auth import Authenticator
from .audit import AuditLogger
from .exceptions import PolicyDenied
from .heuristics import PromptHeuristics
from .policy import Policy
from .rate_limit import RateLimiter
from .types import Finding, GuardDecision


GuardedTool = Callable[..., Awaitable[Any]]


class Guard:
    """Main guard middleware object."""

    def __init__(
        self,
        policy: Policy,
        *,
        time_func: Callable[[], float] | None = None,
        redis_client: Any | None = None,
    ) -> None:
        self.policy = policy
        self.authenticator = Authenticator(policy.auth)
        self.rate_limiter = RateLimiter(policy.rate_limit, time_func=time_func, redis_client=redis_client)
        self.acl = ResourceACL(policy.resources.allow, policy.resources.deny)
        self.heuristics = PromptHeuristics(policy.prompts.compiled_patterns)
        self.audit = AuditLogger(policy.logging, policy.version)
        self._attestation_enabled = policy.attestation.enabled
        self._attestation_alg = policy.attestation.alg

    def identify(self, headers: dict[str, str] | None) -> str:
        return self.authenticator.identify(headers or {})

    async def check_resource(self, identity: str, uri: str) -> GuardDecision:
        allowed = self.acl.is_allowed(uri)
        decision = GuardDecision(
            allowed=allowed,
            reason="Allowed" if allowed else "ResourceDenied",
            findings=[],
        )
        if not allowed:
            self.audit.log(
                identity=identity,
                resource=uri,
                action="resource",
                decision="deny",
                findings=[],
            )
            raise PolicyDenied(message="Resource access denied", details={"uri": uri})
        return decision

    async def check_tool(
        self,
        identity: str,
        tool_name: str,
        *,
        prompt_text: str | None = None,
        resources: Iterable[str] | None = None,
    ) -> GuardDecision:
        normalized_tool = tool_name.replace("/", ".")
        quota_remaining = await self.rate_limiter.get_remaining(identity, normalized_tool)
        if quota_remaining <= 0:
            decision = GuardDecision(
                allowed=False,
                reason="RateLimitExceeded",
                findings=[],
                quota_remaining=0,
            )
            self.audit.log(
                identity=identity,
                tool=normalized_tool,
                action="tool",
                decision="deny",
                findings=[],
            )
            raise PolicyDenied(message="Rate limit exceeded", details={"tool": normalized_tool})

        if not self.policy.tool_allowed(normalized_tool):
            self.audit.log(
                identity=identity,
                tool=normalized_tool,
                action="tool",
                decision="deny",
                findings=[],
            )
            raise PolicyDenied(message="Tool not allowed", details={"tool": normalized_tool})

        findings: list[Finding] = []
        if prompt_text is not None:
            if len(prompt_text) > self.policy.prompts.max_length:
                findings.append(Finding(rule_id="prompt_length", reason="Prompt too long", severity="medium"))
            findings.extend(self.heuristics.evaluate(prompt_text))
            if findings:
                self.audit.log(
                    identity=identity,
                    tool=normalized_tool,
                    action="tool",
                    decision="deny",
                    findings=[asdict(finding) for finding in findings],
                )
                raise PolicyDenied(
                    message="Prompt injection suspected",
                    details={"tool": normalized_tool, "findings": [asdict(finding) for finding in findings]},
                )

        for uri in resources or []:
            if not self.acl.is_allowed(uri):
                self.audit.log(
                    identity=identity,
                    tool=normalized_tool,
                    resource=uri,
                    action="tool",
                    decision="deny",
                    findings=[],
                )
                raise PolicyDenied(message="Resource denied", details={"uri": uri})

        allowed = await self.rate_limiter.consume(identity, normalized_tool)
        if not allowed:
            self.audit.log(
                identity=identity,
                tool=normalized_tool,
                action="tool",
                decision="deny",
                findings=[],
            )
            raise PolicyDenied(message="Rate limit exceeded", details={"tool": normalized_tool})
        quota_after = await self.rate_limiter.get_remaining(identity, normalized_tool)
        return GuardDecision(allowed=True, reason="Allowed", findings=[], quota_remaining=quota_after)

    def wrap_tool(self, func: Callable[..., Awaitable[Any]] | None = None, *, tool_name: str | None = None):
        """Wrap a tool function enforcing policy checks."""

        def decorator(inner: Callable[..., Awaitable[Any]]) -> GuardedTool:
            name = tool_name or inner.__name__
            normalized_tool = name.replace("/", ".")

            if not asyncio.iscoroutinefunction(inner):
                raise TypeError("Wrapped tool must be async")

            @wraps(inner)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                context = kwargs.pop("_guard_context", {})
                identity = context.get("identity", "anonymous")
                prompt = context.get("prompt")
                resources = context.get("resources", [])
                decision = await self.check_tool(
                    identity,
                    normalized_tool,
                    prompt_text=prompt,
                    resources=resources,
                )
                request_hash = None
                if self._attestation_enabled:
                    request_hash = hash_payload({"args": args, "kwargs": kwargs, "context": context}, self._attestation_alg)
                result = await inner(*args, **kwargs)
                response_hash = None
                if self._attestation_enabled:
                    response_hash = hash_payload(result, self._attestation_alg)
                self.audit.log(
                    identity=identity,
                    tool=normalized_tool,
                    action="tool",
                    decision="allow",
                    findings=[asdict(finding) for finding in decision.findings],
                    request_hash=request_hash,
                    response_hash=response_hash,
                )
                return result

            return wrapper

        if func is not None:
            return decorator(func)
        return decorator
