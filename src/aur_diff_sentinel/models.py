from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from re import Pattern
from typing import Callable


class Severity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    pattern: Pattern[str] | None
    message: str
    hint: str
    matcher: Callable[["SourceLine"], bool] | None = None

    @classmethod
    def regex(
        cls,
        *,
        id: str,
        severity: Severity,
        pattern: str,
        message: str,
        hint: str,
        flags: int = re.IGNORECASE,
    ) -> "Rule":
        return cls(
            id=id,
            severity=severity,
            pattern=re.compile(pattern, flags),
            message=message,
            hint=hint,
        )

    @classmethod
    def contextual(
        cls,
        *,
        id: str,
        severity: Severity,
        matcher: Callable[["SourceLine"], bool],
        message: str,
        hint: str,
    ) -> "Rule":
        return cls(
            id=id,
            severity=severity,
            pattern=None,
            message=message,
            hint=hint,
            matcher=matcher,
        )

    def matches(self, line: "SourceLine") -> bool:
        if self.matcher is not None:
            return self.matcher(line)
        if self.pattern is None:
            return False
        return self.pattern.search(line.content) is not None


@dataclass(frozen=True)
class SourceLine:
    line_number: int
    content: str
    filename: str | None = None
    source_type: str = "file"
    diff_line_number: int | None = None
    target_line_number: int | None = None
    change_type: str | None = None
    function_name: str | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    line_number: int
    line_content: str
    hint: str
    filename: str | None = None
    source_type: str = "file"
    diff_line_number: int | None = None
    target_line_number: int | None = None
    change_type: str | None = None
    function_name: str | None = None
