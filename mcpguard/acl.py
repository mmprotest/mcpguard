"""Resource Access Control Lists."""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Iterable


class ResourceACL:
    """Simple glob/regex-based ACL for resource URIs."""

    def __init__(self, allow: Iterable[str], deny: Iterable[str]) -> None:
        self.allow_patterns = list(allow)
        self.deny_patterns = list(deny)

    def is_allowed(self, uri: str) -> bool:
        for pattern in self.deny_patterns:
            if fnmatch(uri, pattern):
                return False
        if not self.allow_patterns:
            return True
        return any(fnmatch(uri, pattern) for pattern in self.allow_patterns)
