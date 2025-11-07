"""Prompt heuristic evaluation."""

from __future__ import annotations

from typing import Iterable

from .types import Finding


class PromptHeuristics:
    """Applies prompt-injection heuristic checks."""

    def __init__(self, deny_patterns: Iterable) -> None:
        self._patterns = list(deny_patterns)

    def evaluate(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for idx, pattern in enumerate(self._patterns):
            if pattern.search(text):
                findings.append(
                    Finding(
                        rule_id=f"prompt_regex_{idx}",
                        severity="high",
                        reason=f"Matched {pattern.pattern}",
                    )
                )
        return findings
