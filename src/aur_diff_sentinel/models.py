from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from re import Pattern


class Severity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    pattern: Pattern[str]
    message: str
    hint: str

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


@dataclass(frozen=True)
class SourceLine:
    line_number: int
    content: str
    filename: str | None = None
    source_type: str = "file"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    line_number: int
    line_content: str
    hint: str
    filename: str | None = None
