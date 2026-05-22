from __future__ import annotations

from collections import Counter

from aur_diff_sentinel.models import Finding, Severity


def format_findings(findings: list[Finding], *, verbose: bool = False) -> str:
    lines: list[str] = []
    counts = Counter(finding.severity for finding in findings)

    if findings:
        for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            severity_findings = [
                finding for finding in findings if finding.severity == severity
            ]
            if not severity_findings:
                continue

            lines.append(severity.value)
            for finding in severity_findings:
                lines.append(_format_finding(finding))
                if verbose:
                    lines.append(f"  line: {finding.line_content}")
                    if finding.hint:
                        lines.append(f"  hint: {finding.hint}")
            lines.append("")

    lines.append(_format_summary(counts))
    lines.append(_format_verdict(findings, counts))
    if not findings:
        lines.append("Manual review is still recommended.")

    return "\n".join(lines)


def _format_finding(finding: Finding) -> str:
    return f"- {_location(finding)} {finding.rule_id:<22} {finding.message}"


def _location(finding: Finding) -> str:
    if finding.filename:
        return f"{finding.filename}:{finding.line_number}"
    return f"line {finding.line_number}"


def _format_summary(counts: Counter[Severity]) -> str:
    return (
        "Summary: "
        f"HIGH {counts[Severity.HIGH]}, "
        f"MEDIUM {counts[Severity.MEDIUM]}, "
        f"LOW {counts[Severity.LOW]}"
    )


def _format_verdict(findings: list[Finding], counts: Counter[Severity]) -> str:
    if counts[Severity.HIGH]:
        return "Verdict: manual review strongly recommended."
    if findings:
        return "Verdict: manual review recommended."
    return "Verdict: no obvious high-risk patterns detected."
