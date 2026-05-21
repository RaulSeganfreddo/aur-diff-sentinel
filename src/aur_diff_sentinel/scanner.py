from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from aur_diff_sentinel.models import Finding, Rule, SourceLine
from aur_diff_sentinel.rules import RULES


HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def source_lines_from_text(text: str, filename: str | None = None) -> list[SourceLine]:
    return [
        SourceLine(line_number=index, content=line, filename=filename, source_type="file")
        for index, line in enumerate(text.splitlines(), start=1)
    ]


def _filename_from_diff_header(line: str) -> str | None:
    parts = line.split(maxsplit=2)
    if len(parts) < 2:
        return None

    path = parts[1]
    if path == "/dev/null":
        return None
    if path.startswith("b/"):
        return path[2:]
    return path


def source_lines_from_diff(text: str, filename: str | None = None) -> list[SourceLine]:
    lines: list[SourceLine] = []
    current_filename = filename
    target_line_number: int | None = None

    for index, line in enumerate(text.splitlines(), start=1):
        if line.startswith("diff --git "):
            current_filename = filename
            target_line_number = None
            continue

        if line.startswith("+++"):
            current_filename = _filename_from_diff_header(line) or filename
            continue

        hunk_match = HUNK_HEADER_RE.match(line)
        if hunk_match:
            target_line_number = int(hunk_match.group(1))
            continue

        if target_line_number is None:
            continue

        if line.startswith("+"):
            lines.append(
                SourceLine(
                    line_number=target_line_number,
                    content=line[1:],
                    filename=current_filename,
                    source_type="diff",
                    diff_line_number=index,
                    target_line_number=target_line_number,
                    change_type="added",
                )
            )
            target_line_number += 1
            continue

        if line.startswith("-"):
            continue

        if line.startswith("\\"):
            continue

        target_line_number += 1

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
                        source_type=line.source_type,
                        diff_line_number=line.diff_line_number,
                        target_line_number=line.target_line_number,
                        change_type=line.change_type,
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
