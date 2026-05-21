from __future__ import annotations

from collections.abc import Iterable, Sequence

from aur_diff_sentinel.models import Finding, Rule, SourceLine
from aur_diff_sentinel.rules import RULES


def source_lines_from_text(text: str, filename: str | None = None) -> list[SourceLine]:
    return [
        SourceLine(line_number=index, content=line, filename=filename, source_type="file")
        for index, line in enumerate(text.splitlines(), start=1)
    ]


def source_lines_from_diff(text: str, filename: str | None = None) -> list[SourceLine]:
    lines: list[SourceLine] = []

    for index, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("+"):
            continue
        if line.startswith("+++"):
            continue

        lines.append(
            SourceLine(
                line_number=index,
                content=line[1:],
                filename=filename,
                source_type="diff",
            )
        )

    return lines


def scan_lines(
    lines: Iterable[SourceLine],
    rules: Sequence[Rule] = RULES,
) -> list[Finding]:
    findings: list[Finding] = []

    for line in lines:
        for rule in rules:
            if rule.pattern.search(line.content):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        message=rule.message,
                        line_number=line.line_number,
                        line_content=line.content,
                        hint=rule.hint,
                        filename=line.filename,
                    )
                )

    return findings


def scan_text(
    text: str,
    rules: Sequence[Rule] = RULES,
    filename: str | None = None,
) -> list[Finding]:
    return scan_lines(source_lines_from_text(text, filename=filename), rules=rules)


def scan_diff_text(
    text: str,
    rules: Sequence[Rule] = RULES,
    filename: str | None = None,
) -> list[Finding]:
    return scan_lines(source_lines_from_diff(text, filename=filename), rules=rules)
