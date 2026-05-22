from __future__ import annotations

from collections import Counter

from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.update_review import UpdateReviewResult


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
                    if finding.old_value is not None:
                        lines.append(f"  old: {finding.old_value}")
                    if finding.new_value is not None:
                        lines.append(f"  new: {finding.new_value}")
                    if finding.hint:
                        lines.append(f"  hint: {finding.hint}")
            lines.append("")

    lines.append(_format_summary(counts))
    lines.append(_format_verdict(findings, counts))
    if not findings:
        lines.append("Manual review is still recommended.")

    return "\n".join(lines)


def format_update_review(result: UpdateReviewResult, *, verbose: bool = False) -> str:
    if not result.reviews:
        return "\n".join(
            [
                "No AUR updates found.",
                "No packages were updated.",
            ]
        )

    lines: list[str] = [f"AUR updates found: {len(result.reviews)}", ""]

    for review in result.reviews:
        lines.append(
            f"{review.update.package}: {review.update.old_version} -> {review.update.new_version}"
        )
        for note in review.notes:
            lines.append(f"  note: {note}")

        if review.findings:
            lines.append(_indent(format_findings(review.findings, verbose=verbose)))
        else:
            lines.append("  No findings.")
        lines.append("")

    if result.refresh_blocked:
        lines.append("Findings were detected, so review baselines were not refreshed.")
        lines.append(
            "If you intentionally accept this state, rerun with: "
            "aur-diff-sentinel baseline refresh --force"
        )
    elif result.refresh_requested:
        lines.append("Review baselines were refreshed.")
    else:
        lines.append("Existing review baselines were not changed.")

    lines.append("No packages were updated.")
    return "\n".join(lines)


def _indent(text: str) -> str:
    return "\n".join(f"  {line}" if line else "" for line in text.splitlines())


def _format_finding(finding: Finding) -> str:
    return f"- {_location(finding)} {finding.rule_id:<26} {finding.message}"


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
