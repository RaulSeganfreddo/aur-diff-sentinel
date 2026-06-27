from __future__ import annotations

from collections import Counter

from aur_diff_sentinel.explanations import EXPLANATIONS
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.update_review import PackageReview, UpdateReviewResult


REASON_PHRASES = {
    "source-domain-changed": "source domain changed",
    "https-to-http-downgrade": "HTTPS changed to HTTP",
    "source-url-added": "source URL added",
    "checksum-skip-added": "checksum SKIP added",
    "checksum-array-removed": "checksum array removed",
    "checksum-algorithm-weakened": "checksum algorithm weakened",
    "checksum-count-mismatch": "source/checksum count mismatch",
    "checksum-skip": "checksum verification skipped",
    "install-script": "install script referenced",
    "install-script-added": "install script added",
    "pacman-hook-added": "pacman hook added",
    "pacman-hook-exec": "pacman hook action",
    "scriptlet-package-manager": "package manager in live script",
    "temporary-directory-package-install": "package install from temporary directory",
    "direct-exec-package-manager": "package manager direct execution",
    "javascript-tooling-dependency-added": "JavaScript tooling dependency added",
    "build-tool-dependency-added": "build-tool dependency added",
    "aur-dependency-added": "AUR dependency added",
    "dependency-added": "new dependency added",
    "dependency-moved": "dependency moved",
    "dependency-removed": "dependency removed",
    "dependency-with-risk-signals": "dependency combined with high-risk signals",
    "aur-metadata-executable-added": "executable metadata file added",
    "aur-metadata-elf-added": "ELF metadata file added",
    "suspicious-live-install-sequence": "combined live install sequence",
    "eval-used": "eval used",
    "curl-pipe-shell": "remote download piped to shell",
    "setuid-permission": "setuid/setgid permission",
    "privilege-command": "live-system command",
    "shell-c": "dynamic shell execution",
    "source-command": "shell source command",
    "decoded-pipe-shell": "decoded content piped into shell",
    "inline-interpreter-command": "inline interpreter command",
    "network-in-build": "network activity during build",
    "writes-outside-pkgdir": "write outside pkgdir",
}
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
                lines.append(_format_finding(finding))
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

    lines.append(_format_summary(counts))
    lines.append(_format_verdict(findings, counts))
    if not findings:
        lines.append("Manual review is still recommended.")

    return "\n".join(lines)


def format_update_review(result: UpdateReviewResult, *, verbose: bool = False, explain: bool = False) -> str:
    if not result.reviews:
        if result.refresh_requested and result.cache_refresh:
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

        if review.findings:
            lines.append(_indent(format_findings(review.findings, verbose=verbose, explain=explain)))
        else:
            lines.append("  No findings.")
        lines.append("")

    if result.refresh_blocked:
        lines.append(
            "Findings were detected, so matching installed baselines were not refreshed."
        )
        lines.append(
            "If you intentionally accept this state, rerun with: "
            "aur-diff-sentinel baseline refresh --force"
        )
    elif result.refresh_requested and result.cache_refresh:
        refreshed_count = sum(1 for review in result.reviews if review.baseline_refreshed)
        if not refreshed_count:
            if visible_reviews:
                lines.append("Review baselines were not refreshed.")
            else:
                lines.append("No baseline refreshes needed.")
    elif result.refresh_requested:
        lines.append("Review baselines were refreshed.")
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
    if not review.findings and not review.notes:
        return False
    if verbose or not result.cache_refresh:
        return True
    return not _is_already_matching_refresh_review(review)


def _is_already_matching_refresh_review(review: PackageReview) -> bool:
    return (
        not review.findings
        and not review.baseline_refreshed
        and not review.refresh_blocked
        and review.notes == ["Review baseline already matches reviewed metadata."]
    )


def _format_attention_summary(reviews: list[PackageReview]) -> list[str]:
    lines: list[str] = []
    high_attention = [review for review in reviews if _highest_severity(review) == Severity.HIGH]
    medium_attention = [
        review
        for review in reviews
        if _highest_severity(review) in {Severity.MEDIUM, Severity.LOW}
    ]
    no_findings = [review for review in reviews if not review.findings]

    if high_attention:
        lines.append("High attention:")
        lines.extend(_format_attention_item(review) for review in high_attention)
        lines.append("")

    if medium_attention:
        lines.append("Medium attention:")
        lines.extend(_format_attention_item(review) for review in medium_attention)
        lines.append("")

    if no_findings:
        lines.append("No findings:")
        lines.extend(f"- {review.update.package}" for review in no_findings)
        lines.append("")

    if high_attention or medium_attention or any(review.notes for review in reviews):
        lines.append("Details:")
        lines.append("")

    return lines


def _highest_severity(review: PackageReview) -> Severity | None:
    severities = {finding.severity for finding in review.findings}
    for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        if severity in severities:
            return severity
    return None


def _format_attention_item(review: PackageReview) -> str:
    return f"- {review.update.package}: {_reason_summary(review.findings)}"


def _reason_summary(findings: list[Finding]) -> str:
    reasons: list[str] = []
    for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        for finding in findings:
            if finding.severity != severity:
                continue
            reason = REASON_PHRASES.get(finding.rule_id, finding.message.lower())
            if reason not in reasons:
                reasons.append(reason)

    shown = reasons[:REASON_LIMIT]
    remaining = len(reasons) - len(shown)
    if remaining:
        shown.append(f"+{remaining} more")
    return ", ".join(shown)


def _indent(text: str) -> str:
    return "\n".join(f"  {line}" if line else "" for line in text.splitlines())


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


def _format_finding(finding: Finding) -> str:
    return f"- {_location(finding)} {finding.rule_id:<26} {finding.message}"


def _finding_context(finding: Finding) -> str:
    parts: list[str] = []
    if finding.function_name:
        parts.append(finding.function_name)
    if finding.execution_context:
        parts.append(f"({finding.execution_context})")
    return " ".join(parts) if parts else "unknown"


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
