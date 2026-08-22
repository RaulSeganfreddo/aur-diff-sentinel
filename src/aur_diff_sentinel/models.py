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
        return cls(id, severity, re.compile(pattern, flags), message, hint)

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
        return cls(id, severity, None, message, hint, matcher)

    def matches(self, line: "SourceLine") -> bool:
        if self.matcher is not None:
            return self.matcher(line)
        return bool(self.pattern and self.pattern.search(line.content))


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
    execution_context: str | None = None


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
    execution_context: str | None = None
    old_value: str | None = None
    new_value: str | None = None

    @classmethod
    def from_source(
        cls,
        source: SourceLine,
        *,
        rule_id: str,
        severity: Severity,
        message: str,
        hint: str,
    ) -> Finding:
        return cls(
            rule_id,
            severity,
            message,
            source.line_number,
            source.content,
            hint,
            source.filename,
            source.source_type,
            source.diff_line_number,
            source.target_line_number,
            source.change_type,
            source.function_name,
            source.execution_context,
        )
