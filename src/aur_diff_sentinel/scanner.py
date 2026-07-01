from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Sequence

from aur_diff_sentinel.correlation import sequence_findings, with_composite_findings
from aur_diff_sentinel.diff_analysis import analyze_source_diff
from aur_diff_sentinel.models import Finding, Rule, SourceLine
from aur_diff_sentinel.pkgbuild_analysis import analyze_pkgbuild_checksums
from aur_diff_sentinel.rules import RULES
from aur_diff_sentinel.source_lines import (
    is_full_line_comment,
    source_lines_from_diff,
    source_lines_from_text,
)


def scan_lines(
    lines: Iterable[SourceLine],
    rules: Sequence[Rule] = RULES,
) -> list[Finding]:
    findings: list[Finding] = []

    for line in lines:
        if is_full_line_comment(line.content):
            continue
        for rule in rules:
            if rule.matches(line):
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
                        function_name=line.function_name,
                        execution_context=line.execution_context,
                    )
                )

    return findings


def scan_text(
    text: str,
    rules: Sequence[Rule] = RULES,
    filename: str | None = None,
    *,
    scriptlet_files: Collection[str] | None = None,
    include_contextual: bool | None = None,
) -> list[Finding]:
    include_contextual = rules is RULES if include_contextual is None else include_contextual
    lines = source_lines_from_text(text, filename=filename, scriptlet_files=scriptlet_files)
    findings = scan_lines(lines, rules=rules)
    if include_contextual:
        findings.extend(sequence_findings(lines))
        findings.extend(analyze_pkgbuild_checksums(text, filename=filename))
        findings = with_composite_findings(findings)
    return _sort_findings_by_source_order(findings)


def _sort_findings_by_source_order(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(
        enumerate(findings),
        key=lambda item: (item[1].line_number, item[0]),
    )
    return [finding for _index, finding in ordered]


def scan_diff_text(
    text: str,
    rules: Sequence[Rule] = RULES,
    filename: str | None = None,
    *,
    scriptlet_files: Collection[str] | None = None,
    is_aur_package: Callable[[str], bool] | None = None,
    include_contextual: bool | None = None,
) -> list[Finding]:
    include_contextual = rules is RULES if include_contextual is None else include_contextual
    lines = source_lines_from_diff(text, filename=filename, scriptlet_files=scriptlet_files)
    line_findings = scan_lines(lines, rules=rules)
    if include_contextual:
        line_findings.extend(sequence_findings(lines))
    diff_findings = analyze_source_diff(text, is_aur_package=is_aur_package)
    contextual_skip_locations = {
        (finding.filename, finding.line_number)
        for finding in diff_findings
        if finding.rule_id == "checksum-skip-added"
    }
    filtered_line_findings = [
        finding
        for finding in line_findings
        if not (
            finding.rule_id == "checksum-skip"
            and (finding.filename, finding.line_number) in contextual_skip_locations
        )
    ]
    findings = [*filtered_line_findings, *diff_findings]
    if include_contextual:
        findings = with_composite_findings(findings)
    return findings
