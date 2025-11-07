"""Custom exceptions for mcpguard."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MCPGuardException(Exception):
    """Base class for mcpguard exceptions."""

    message: str
    http_status: int = 400
    details: dict[str, object] | None = None

    def __str__(self) -> str:  # pragma: no cover - dataclass str wrapper
        return self.message


class Unauthorized(MCPGuardException):
    """Raised when authentication fails."""

    http_status: int = 401


class PolicyDenied(MCPGuardException):
    """Raised when the guard denies an action."""

    http_status: int = 403


class BadPolicy(MCPGuardException):
    """Raised when a policy file cannot be parsed or validated."""

    http_status: int = 422
