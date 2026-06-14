from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from aur_diff_sentinel.baseline_prune import SelectionError, parse_prune_selection
from aur_diff_sentinel.cache import AurCache, metadata_version, unified_diff_dirs
from aur_diff_sentinel.cli import run
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.provider import (
    AurUpdate,
    InstalledPackageStatus,
    discover_updates,
    parse_update_output,
    query_installed_package,
)
from aur_diff_sentinel.report import format_findings, format_update_review
from aur_diff_sentinel.scanner import scan_diff_text, scan_text, source_lines_from_diff, source_lines_from_text
from aur_diff_sentinel.update_review import (
    PackageReview,
    UpdateReviewResult,
    refresh_cached_reviewed_baselines,
    refresh_reviewed_baselines,
    review_updates,
)

from tests.helpers import (
    SAMPLES,
    copy_repo_fetcher,
    finding as _finding,
    fixture_fetcher,
    rule_ids,
    run_git,
    write_metadata,
)

class ReportTests(unittest.TestCase):
    def test_clean_report_is_compact(self) -> None:
        report = format_findings([])

        self.assertEqual(
            report,
            "\n".join(
                [
                    "Summary: HIGH 0, MEDIUM 0, LOW 0",
                    "Verdict: no obvious high-risk patterns detected.",
                    "Manual review is still recommended.",
                ]
            ),
        )

    def test_default_report_groups_by_severity_without_verbose_details(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "pkgname=example",
                    "sha256sums=('SKIP')",
                    "install=example.install",
                    "prepare() {",
                    "    curl https://example.com/install.sh | bash",
                    "}",
                ]
            ),
            filename="PKGBUILD",
        )
        report = format_findings(findings)

        self.assertLess(report.index("HIGH\n"), report.index("MEDIUM\n"))
        self.assertIn("- PKGBUILD:2 checksum-skip", report)
        self.assertIn("- PKGBUILD:5 network-in-build", report)
        self.assertIn("- PKGBUILD:3 install-script", report)
        self.assertIn("Summary: HIGH 3, MEDIUM 1, LOW 0", report)
        self.assertNotIn("hint:", report)
        self.assertNotIn("line:", report)

    def test_verbose_report_includes_lines_and_hints(self) -> None:
        findings = scan_text("sha256sums=('SKIP')", filename="PKGBUILD")
        report = format_findings(findings, verbose=True)

        self.assertIn("line: sha256sums=('SKIP')", report)
        self.assertIn("hint: SKIP skips source verification", report)

    def test_verbose_report_includes_old_and_new_values(self) -> None:
        findings = scan_diff_text((SAMPLES / "source-change.diff").read_text(encoding="utf-8"))
        report = format_findings(findings, verbose=True)

        self.assertIn("old: https://github.com/example/app/archive/v1.0.tar.gz", report)
        self.assertIn("new: http://downloads.example.net/app/v1.0.tar.gz", report)

    def test_cached_refresh_report_shows_refreshed_count(self) -> None:
        result = UpdateReviewResult(
            reviews=[
                PackageReview(
                    update=AurUpdate("example-bin", "1.0-1", "1.1-1"),
                    notes=["Refreshed review baseline from cached metadata."],
                    baseline_refreshed=True,
                )
            ],
            refresh_requested=True,
            cache_refresh=True,
        )
        report = format_update_review(result)

        self.assertIn("Review baselines refreshed: 1", report)
        self.assertIn("example-bin: 1.0-1 -> 1.1-1", report)
        self.assertNotIn("Review baselines were refreshed from cached metadata.", report)
        self.assertIn("No packages were updated.", report)

    def test_cached_refresh_report_hides_already_matching_packages_by_default(self) -> None:
        result = UpdateReviewResult(
            reviews=[
                PackageReview(
                    update=AurUpdate("refreshed-pkg", "1.0-1", "1.1-1"),
                    notes=["Refreshed review baseline for installed version 1.1-1."],
                    baseline_refreshed=True,
                ),
                PackageReview(
                    update=AurUpdate("already-current-pkg", "2.0-1", "2.0-1"),
                    notes=["Review baseline already matches reviewed metadata."],
                ),
            ],
            refresh_requested=True,
            cache_refresh=True,
        )
        report = format_update_review(result)

        self.assertIn("refreshed-pkg: 1.0-1 -> 1.1-1", report)
        self.assertNotIn("already-current-pkg", report)

    def test_verbose_cached_refresh_report_shows_already_matching_packages(self) -> None:
        result = UpdateReviewResult(
            reviews=[
                PackageReview(
                    update=AurUpdate("already-current-pkg", "2.0-1", "2.0-1"),
                    notes=["Review baseline already matches reviewed metadata."],
                )
            ],
            refresh_requested=True,
            cache_refresh=True,
        )
        report = format_update_review(result, verbose=True)

        self.assertIn("already-current-pkg: 2.0-1 -> 2.0-1", report)
        self.assertIn("Review baseline already matches reviewed metadata.", report)

    def test_cached_refresh_report_explains_noop_when_everything_already_matches(self) -> None:
        result = UpdateReviewResult(
            reviews=[
                PackageReview(
                    update=AurUpdate("already-current-pkg", "2.0-1", "2.0-1"),
                    notes=["Review baseline already matches reviewed metadata."],
                )
            ],
            refresh_requested=True,
            cache_refresh=True,
        )
        report = format_update_review(result)

        self.assertIn("No baseline refreshes needed.", report)
        self.assertNotIn("Review baselines were not refreshed.", report)

    def test_cached_refresh_report_explains_no_refresh_candidates(self) -> None:
        result = UpdateReviewResult(
            reviews=[],
            refresh_requested=True,
            cache_refresh=True,
        )
        report = format_update_review(result)

        self.assertEqual(
            report,
            "\n".join(
                [
                    "No pending AUR updates found.",
                    "No reviewed metadata was ready to refresh.",
                    "No packages were updated.",
                ]
            ),
        )

    def test_update_report_groups_packages_by_attention(self) -> None:
        result = UpdateReviewResult(
            reviews=[
                PackageReview(
                    update=AurUpdate("high-pkg", "1.0-1", "1.1-1"),
                    findings=[
                        _finding("source-domain-changed", Severity.HIGH),
                        _finding("checksum-skip-added", Severity.HIGH),
                    ],
                ),
                PackageReview(
                    update=AurUpdate("clean-pkg", "2.0-1", "2.1-1"),
                ),
                PackageReview(
                    update=AurUpdate("medium-pkg", "3.0-1", "3.1-1"),
                    findings=[_finding("install-script", Severity.MEDIUM)],
                ),
            ]
        )
        report = format_update_review(result)

        self.assertLess(report.index("High attention:"), report.index("Medium attention:"))
        self.assertLess(report.index("Medium attention:"), report.index("No findings:"))
        self.assertIn("- high-pkg: source domain changed, checksum SKIP added", report)
        self.assertIn("- medium-pkg: install script referenced", report)
        self.assertIn("- clean-pkg", report)
        self.assertIn("Details:", report)
        self.assertIn("high-pkg: 1.0-1 -> 1.1-1", report)
        self.assertIn("medium-pkg: 3.0-1 -> 3.1-1", report)
        self.assertNotIn("clean-pkg: 2.0-1 -> 2.1-1", report)

    def test_update_report_reason_summary_is_deduplicated_and_capped(self) -> None:
        result = UpdateReviewResult(
            reviews=[
                PackageReview(
                    update=AurUpdate("busy-pkg", "1.0-1", "1.1-1"),
                    findings=[
                        _finding("source-domain-changed", Severity.HIGH),
                        _finding("source-domain-changed", Severity.HIGH),
                        _finding("checksum-skip-added", Severity.HIGH),
                        _finding("curl-pipe-shell", Severity.HIGH),
                        _finding("install-script", Severity.MEDIUM),
                    ],
                )
            ]
        )
        report = format_update_review(result)

        self.assertIn(
            "- busy-pkg: source domain changed, checksum SKIP added, "
            "remote download piped to shell, +1 more",
            report,
        )

    def test_update_report_keeps_note_only_package_details(self) -> None:
        result = UpdateReviewResult(
            reviews=[
                PackageReview(
                    update=AurUpdate("note-pkg", "1.0-1", "1.1-1"),
                    notes=["No review baseline could be found."],
                )
            ]
        )
        report = format_update_review(result)

        self.assertIn("No findings:", report)
        self.assertIn("- note-pkg", report)
        self.assertIn("Details:", report)
        self.assertIn("note-pkg: 1.0-1 -> 1.1-1", report)
        self.assertIn("note: No review baseline could be found.", report)

    def test_update_report_verbose_still_includes_finding_details(self) -> None:
        result = UpdateReviewResult(
            reviews=[
                PackageReview(
                    update=AurUpdate("verbose-pkg", "1.0-1", "1.1-1"),
                    findings=[
                        _finding(
                            "source-domain-changed",
                            Severity.HIGH,
                            old_value="https://old.example/app.tar.gz",
                            new_value="https://new.example/app.tar.gz",
                        )
                    ],
                )
            ]
        )
        report = format_update_review(result, verbose=True)

        self.assertIn("line: sha256sums=('SKIP')", report)
        self.assertIn("old: https://old.example/app.tar.gz", report)
        self.assertIn("new: https://new.example/app.tar.gz", report)
        self.assertIn("hint: review this finding", report)


def _finding(
    rule_id: str,
    severity: Severity,
    *,
    old_value: str | None = None,
    new_value: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=rule_id.replace("-", " "),
        line_number=4,
        line_content="sha256sums=('SKIP')",
        hint="review this finding",
        filename="PKGBUILD",
        old_value=old_value,
        new_value=new_value,
    )


