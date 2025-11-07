"""Attestation helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def hash_payload(payload: Any, alg: str = "sha256") -> str:
    """Hash a payload using the provided algorithm."""

    serialized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    try:
        hasher = hashlib.new(alg)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Unsupported hash algorithm: {alg}") from exc
    hasher.update(serialized)
    return hasher.hexdigest()
