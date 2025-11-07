"""Structured audit logging."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Optional

from .policy import LoggingSettings


class AuditLogger:
    """Writes audit events as JSON lines."""

    def __init__(self, settings: LoggingSettings, policy_version: int) -> None:
        self.logger = logging.getLogger("mcpguard.audit")
        if not self.logger.handlers:
            handler: logging.Handler
            if settings.output == "file":
                handler = RotatingFileHandler(
                    settings.file_path,
                    maxBytes=settings.rotate_bytes,
                    backupCount=3,
                )
            else:
                handler = logging.StreamHandler()
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.logger.setLevel(getattr(logging, settings.level.upper(), logging.INFO))
        self.policy_version = policy_version

    def log(
        self,
        *,
        identity: str,
        tool: Optional[str] = None,
        resource: Optional[str] = None,
        action: str,
        decision: str,
        findings: list[dict[str, Any]] | None = None,
        latency_ms: float | None = None,
        request_hash: str | None = None,
        response_hash: str | None = None,
    ) -> None:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "identity": identity,
            "tool": tool,
            "resource": resource,
            "action": action,
            "decision": decision,
            "findings": findings or [],
            "latency_ms": latency_ms,
            "request_hash": request_hash,
            "response_hash": response_hash,
            "policy_version": self.policy_version,
        }
        self.logger.info(json.dumps(payload))
