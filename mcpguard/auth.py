"""Authentication helpers."""

from __future__ import annotations

from typing import Mapping

from .exceptions import Unauthorized
from .policy import AuthSettings


class Authenticator:
    """Extracts identities based on configured authentication mode."""

    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings

    def identify(self, headers: Mapping[str, str] | None) -> str:
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        if self.settings.mode == "none":
            return "anonymous"
        if self.settings.mode == "api_key":
            key = headers.get("x-api-key")
            if key and key in self.settings.allowed_keys:
                return key
            raise Unauthorized(message="Invalid API key")
        if self.settings.mode == "bearer":
            auth_header = headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1]
                if token in self.settings.allowed_tokens:
                    return token
            raise Unauthorized(message="Invalid bearer token")
        raise Unauthorized(message="Unsupported authentication mode")
