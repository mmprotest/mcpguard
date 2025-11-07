"""Shared data structures for mcpguard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(slots=True)
class Finding:
    """Represents a heuristic finding."""

    rule_id: str
    reason: str
    severity: str


@dataclass(slots=True)
class GuardDecision:
    """Result of a guard evaluation."""

    allowed: bool
    reason: str
    findings: list[Finding] = field(default_factory=list)
    quota_remaining: Optional[int] = None


@dataclass(slots=True)
class Metrics:
    """Simple counter metrics for the proxy control plane."""

    allowed: int = 0
    denied: int = 0
    errors: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "denied": self.denied, "errors": self.errors}
