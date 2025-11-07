"""Policy loading and validation for mcpguard."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator, PrivateAttr

from .exceptions import BadPolicy


class AuthSettings(BaseModel):
    mode: Literal["none", "api_key", "bearer"] = "none"
    allowed_keys: list[str] = Field(default_factory=list)
    allowed_tokens: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_credentials(self) -> "AuthSettings":
        if self.mode == "api_key" and not self.allowed_keys:
            msg = "auth.allowed_keys must be provided for api_key mode"
            raise ValueError(msg)
        if self.mode == "bearer" and not self.allowed_tokens:
            msg = "auth.allowed_tokens must be provided for bearer mode"
            raise ValueError(msg)
        return self


class ToolPolicy(BaseModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class ResourcePolicy(BaseModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class PromptSettings(BaseModel):
    deny_regex: list[str] = Field(default_factory=list)
    max_length: int = 4000
    _compiled_patterns: list[Any] = PrivateAttr(default_factory=list)

    @field_validator("max_length")
    @classmethod
    def validate_length(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("max_length must be positive")
        return value

    @model_validator(mode="after")
    def compile_patterns(self) -> "PromptSettings":
        import re

        self._compiled_patterns = [re.compile(pattern) for pattern in self.deny_regex]
        return self

    @property
    def compiled_patterns(self) -> list[Any]:
        return self._compiled_patterns


class RateLimitSettings(BaseModel):
    capacity: int = 30
    refill_rate_per_sec: float = 1.0
    backend: Literal["memory", "redis"] = "memory"
    redis_dsn: str | None = None

    @model_validator(mode="after")
    def validate_values(self) -> "RateLimitSettings":
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        if self.refill_rate_per_sec <= 0:
            raise ValueError("refill_rate_per_sec must be positive")
        if self.backend == "redis" and not self.redis_dsn:
            raise ValueError("redis backend requires redis_dsn")
        return self


class LoggingSettings(BaseModel):
    level: str = "INFO"
    output: Literal["stderr", "file"] = "stderr"
    file_path: str = "mcpguard.log"
    rotate_bytes: int = 10_485_760


class AttestationSettings(BaseModel):
    enabled: bool = False
    alg: Literal["sha256", "sha512"] = "sha256"


class Policy(BaseModel):
    version: int = 1
    auth: AuthSettings = Field(default_factory=AuthSettings)
    tools: ToolPolicy = Field(default_factory=ToolPolicy)
    resources: ResourcePolicy = Field(default_factory=ResourcePolicy)
    prompts: PromptSettings = Field(default_factory=PromptSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    attestation: AttestationSettings = Field(default_factory=AttestationSettings)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        try:
            return cls.model_validate(data)
        except ValidationError as exc:  # pragma: no cover - thin wrapper
            raise BadPolicy(message=str(exc)) from exc

    def tool_allowed(self, tool_name: str) -> bool:
        from fnmatch import fnmatch

        normalized = tool_name.replace("/", ".")
        for pattern in self.tools.deny:
            if fnmatch(normalized, pattern.replace("/", ".")):
                return False
        if self.tools.allow:
            return any(fnmatch(normalized, pat.replace("/", ".")) for pat in self.tools.allow)
        return True

    def resource_allowed(self, uri: str) -> bool:
        from fnmatch import fnmatch

        for pattern in self.resources.deny:
            if fnmatch(uri, pattern):
                return False
        if self.resources.allow:
            return any(fnmatch(uri, pattern) for pattern in self.resources.allow)
        return True


def load_policy(path: str | Path) -> Policy:
    """Load a policy from a YAML file."""

    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - direct passthrough
        raise BadPolicy(message=f"Failed to read policy: {exc}") from exc
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - YAML parse errors
        raise BadPolicy(message=f"Failed to parse policy YAML: {exc}") from exc
    return Policy.from_dict(data)
