from __future__ import annotations

from collections import Counter

from aur_diff_sentinel.explanations import EXPLANATIONS, reason_phrase
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.update_review import PackageReview, UpdateReviewResult


REASON_LIMIT = 3


def format_findings(findings: list[Finding], *, verbose: bool = False, explain: bool = False) -> str:
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
                lines.append(f"- {_location(finding)} {finding.rule_id:<26} {finding.message}")
                if explain:
                    explanation = _format_explanation(finding)
                    if explanation:
                        lines.append(explanation)
                if verbose:
                    lines.append(f"  line: {finding.line_content}")
                    if finding.execution_context or finding.function_name:
                        lines.append(f"  context: {_finding_context(finding)}")
                    if finding.old_value is not None:
                        lines.append(f"  old: {finding.old_value}")
                    if finding.new_value is not None:
                        lines.append(f"  new: {finding.new_value}")
                    if finding.hint:
                        lines.append(f"  hint: {finding.hint}")
            lines.append("")

    lines.append("Summary: " + ", ".join(f"{severity.value} {counts[severity]}" for severity in Severity))
    lines.append(_format_verdict(findings, counts))
    if not findings:
        lines.append("Manual review is still recommended.")

    return "\n".join(lines)


def format_update_review(result: UpdateReviewResult, *, verbose: bool = False, explain: bool = False) -> str:
    if not result.reviews:
        if result.cache_refresh:
            lines = ["No reviewed metadata was ready to refresh."]
            if not result.pending_update_count:
                lines.insert(0, "No pending AUR updates found.")
            lines.append("No packages were updated.")
            return "\n".join(lines)
        return "\n".join(
            [
                "No AUR updates found.",
                "No packages were updated.",
            ]
        )

    if result.cache_refresh:
        lines = _format_cache_refresh_header(result)
    else:
        lines = [f"AUR updates found: {len(result.reviews)}", ""]
        lines.extend(_format_attention_summary(result.reviews))

    visible_reviews = [
        review
        for review in result.reviews
        if _should_show_review(result, review, verbose=verbose)
    ]
    for review in visible_reviews:
        lines.append(
            f"{review.update.package}: {review.update.old_version} -> {review.update.new_version}"
        )
        for note in review.notes:
            lines.append(f"  note: {note}")
        for error in review.analysis_errors:
            lines.append(f"  warning: {error}")

        if review.findings:
            finding_report = format_findings(review.findings, verbose=verbose, explain=explain)
            lines.append("\n".join(f"  {line}" if line else "" for line in finding_report.splitlines()))
        elif review.analysis_errors:
            lines.append("  Analysis incomplete.")
        else:
            lines.append("  No findings.")
        lines.append("")

    if result.analysis_incomplete:
        lines.append("Some package metadata could not be analyzed.")
        if result.cache_refresh:
            lines.append("Review baselines were not refreshed for incomplete analyses.")
        else:
            lines.append("Existing review baselines were not changed.")
    elif result.refresh_blocked:
        lines.append(
            "Findings were detected, so matching installed baselines were not refreshed."
        )
        lines.append(
            "If you intentionally accept this state, rerun with: "
            "aur-diff-sentinel baseline refresh --force"
        )
    elif result.cache_refresh:
        refreshed_count = sum(1 for review in result.reviews if review.baseline_refreshed)
        if not refreshed_count:
            if visible_reviews:
                lines.append("Review baselines were not refreshed.")
            else:
                lines.append("No baseline refreshes needed.")
    else:
        lines.append("Existing review baselines were not changed.")

    lines.append("No packages were updated.")
    return "\n".join(lines)


def _format_cache_refresh_header(result: UpdateReviewResult) -> list[str]:
    refreshed_count = sum(1 for review in result.reviews if review.baseline_refreshed)
    if refreshed_count:
        return [
            f"Review baselines refreshed: {refreshed_count}",
            "",
        ]
    lines: list[str] = []
    if not result.pending_update_count:
        lines.append("No pending AUR updates found.")
    lines.extend(
        [
            "Reviewed metadata was checked for refresh candidates.",
            "",
        ]
    )
    return lines


def _should_show_review(
    result: UpdateReviewResult,
    review: PackageReview,
    *,
    verbose: bool,
) -> bool:
    if not review.findings and not review.notes and not review.analysis_errors:
        return False
    if verbose or not result.cache_refresh:
        return True
    return not _is_already_matching_refresh_review(review)


def _is_already_matching_refresh_review(review: PackageReview) -> bool:
    return (
        not review.findings
        and not review.analysis_errors
        and not review.baseline_refreshed
        and not review.refresh_blocked
        and review.notes == ["Review baseline already matches reviewed metadata."]
    )


def _format_attention_summary(reviews: list[PackageReview]) -> list[str]:
    lines: list[str] = []
    groups = [
        (
            f"{severity.value.title()} attention:",
            [review for review in reviews if _highest_severity(review) == severity],
            _format_attention_item,
        )
        for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    ]
    groups.extend(
        (
            ("Incomplete analysis:", [review for review in reviews if review.analysis_errors], _package_item),
            (
                "No findings:",
                [review for review in reviews if not review.findings and not review.analysis_errors],
                _package_item,
            ),
        )
    )
    for title, group, formatter in groups:
        if group:
            lines.extend((title, *(formatter(review) for review in group), ""))

    if any(review.findings or review.analysis_errors or review.notes for review in reviews):
        lines.append("Details:")
        lines.append("")

    return lines


def _highest_severity(review: PackageReview) -> Severity | None:
    severities = {finding.severity for finding in review.findings}
    return next((severity for severity in Severity if severity in severities), None)


def _format_attention_item(review: PackageReview) -> str:
    return f"- {review.update.package}: {_reason_summary(review.findings)}"


def _package_item(review: PackageReview) -> str:
    return f"- {review.update.package}"


def _reason_summary(findings: list[Finding]) -> str:
    reasons: list[str] = []
    for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        for finding in findings:
            if finding.severity != severity:
                continue
            reason = reason_phrase(finding.rule_id, finding.message.lower())
            if reason not in reasons:
                reasons.append(reason)

    shown = reasons[:REASON_LIMIT]
    remaining = len(reasons) - len(shown)
    if remaining:
        shown.append(f"+{remaining} more")
    return ", ".join(shown)


def _format_explanation(finding: Finding) -> str:
    explanation = EXPLANATIONS.get(finding.rule_id)
    if explanation is None:
        return ""
    return "\n".join(
        [
            "",
            f"  What:    {explanation.what}",
            f"  Why:     {explanation.why}",
            f"  Inspect: {explanation.inspect}",
        ]
    )


def _finding_context(finding: Finding) -> str:
    parts = [
        part
        for part in (finding.function_name, f"({finding.execution_context})" if finding.execution_context else None)
        if part
    ]
    return " ".join(parts) if parts else "unknown"


def _location(finding: Finding) -> str:
    if finding.filename:
        return f"{finding.filename}:{finding.line_number}"
    return f"line {finding.line_number}"


def _format_verdict(findings: list[Finding], counts: Counter[Severity]) -> str:
    if counts[Severity.HIGH]:
        return "Verdict: manual review strongly recommended."
    if findings:
        return "Verdict: manual review recommended."
    return "Verdict: no obvious high-risk patterns detected."
