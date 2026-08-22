from __future__ import annotations

import unittest

from aur_diff_sentinel.explanations import EXPLANATIONS
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.provider import AurUpdate
from aur_diff_sentinel.report import format_findings, format_update_review
from aur_diff_sentinel.scanner import scan_diff_text, scan_text
from aur_diff_sentinel.update_review import PackageReview, UpdateReviewResult
from tests.helpers import SAMPLES, finding


def review(package: str, old: str = "1.0-1", new: str = "1.1-1", **state) -> PackageReview:
    return PackageReview(AurUpdate(package, old, new), **state)


def result(*reviews: PackageReview, cache_refresh: bool = False) -> UpdateReviewResult:
    return UpdateReviewResult(list(reviews), cache_refresh=cache_refresh)


class ReportTests(unittest.TestCase):
    def test_clean_report_is_compact(self) -> None:
        self.assertEqual(
            format_findings([]),
            "\n".join(
                (
                    "Summary: HIGH 0, MEDIUM 0, LOW 0",
                    "Verdict: no obvious high-risk patterns detected.",
                    "Manual review is still recommended.",
                )
            ),
        )

    def test_default_report_groups_by_severity_without_verbose_details(self) -> None:
        findings = scan_text(
            "\n".join(
                (
                    "pkgname=example",
                    "sha256sums=('SKIP')",
                    "install=example.install",
                    "prepare() {",
                    "    curl https://example.com/install.sh | bash",
                    "}",
                )
            ),
            filename="PKGBUILD",
        )
        report = format_findings(findings)
        self.assertLess(report.index("HIGH\n"), report.index("MEDIUM\n"))
        for text in (
            "- PKGBUILD:2 checksum-skip",
            "- PKGBUILD:5 network-in-build",
            "- PKGBUILD:3 install-script",
            "Summary: HIGH 3, MEDIUM 1, LOW 0",
        ):
            self.assertIn(text, report)
        self.assertNotIn("hint:", report)
        self.assertNotIn("line:", report)

    def test_verbose_report_includes_lines_hints_and_changed_values(self) -> None:
        report = format_findings(scan_text("sha256sums=('SKIP')", filename="PKGBUILD"), verbose=True)
        self.assertIn("line: sha256sums=('SKIP')", report)
        self.assertIn("hint: SKIP skips source verification", report)
        changed = format_findings(
            scan_diff_text((SAMPLES / "source-change.diff").read_text(encoding="utf-8")),
            verbose=True,
        )
        self.assertIn("old: https://github.com/example/app/archive/v1.0.tar.gz", changed)
        self.assertIn("new: http://downloads.example.net/app/v1.0.tar.gz", changed)

    def test_cached_refresh_report_shows_refreshed_count(self) -> None:
        report = format_update_review(
            result(
                review(
                    "example-bin",
                    notes=["Refreshed review baseline from cached metadata."],
                    baseline_refreshed=True,
                ),
                cache_refresh=True,
            )
        )
        for text in ("Review baselines refreshed: 1", "example-bin: 1.0-1 -> 1.1-1", "No packages were updated."):
            self.assertIn(text, report)
        self.assertNotIn("Review baselines were refreshed from cached metadata.", report)

    def test_cached_refresh_already_matching_visibility_and_noop(self) -> None:
        current = review(
            "already-current-pkg",
            "2.0-1",
            "2.0-1",
            notes=["Review baseline already matches reviewed metadata."],
        )
        refreshed = review(
            "refreshed-pkg",
            notes=["Refreshed review baseline for installed version 1.1-1."],
            baseline_refreshed=True,
        )
        cases = (
            ("hidden-by-default", result(refreshed, current, cache_refresh=True), False, False),
            ("shown-when-verbose", result(current, cache_refresh=True), True, True),
            ("noop-explained", result(current, cache_refresh=True), False, False),
        )
        for name, data, verbose, visible in cases:
            with self.subTest(name=name):
                report = format_update_review(data, verbose=verbose)
                self.assertEqual("already-current-pkg: 2.0-1 -> 2.0-1" in report, visible)
                if name == "noop-explained":
                    self.assertIn("No baseline refreshes needed.", report)
                    self.assertNotIn("Review baselines were not refreshed.", report)

    def test_cached_refresh_report_explains_no_refresh_candidates(self) -> None:
        self.assertEqual(
            format_update_review(result(cache_refresh=True)),
            "\n".join(
                (
                    "No pending AUR updates found.",
                    "No reviewed metadata was ready to refresh.",
                    "No packages were updated.",
                )
            ),
        )

    def test_update_report_groups_packages_by_attention(self) -> None:
        report = format_update_review(
            result(
                review(
                    "high-pkg",
                    findings=[
                        finding("source-domain-changed", Severity.HIGH),
                        finding("checksum-skip-added", Severity.HIGH),
                    ],
                ),
                review("clean-pkg", "2.0-1", "2.1-1"),
                review("medium-pkg", "3.0-1", "3.1-1", findings=[finding("install-script", Severity.MEDIUM)]),
                review("low-pkg", "4.0-1", "4.1-1", findings=[finding("dependency-added", Severity.LOW)]),
            )
        )
        headings = ("High attention:", "Medium attention:", "Low attention:", "No findings:")
        self.assertEqual(sorted(map(report.index, headings)), list(map(report.index, headings)))
        for text in (
            "- high-pkg: source domain changed, checksum SKIP added",
            "- medium-pkg: install script referenced",
            "- low-pkg: new dependency added",
            "- clean-pkg",
            "Details:",
            "high-pkg: 1.0-1 -> 1.1-1",
            "medium-pkg: 3.0-1 -> 3.1-1",
            "low-pkg: 4.0-1 -> 4.1-1",
        ):
            self.assertIn(text, report)
        self.assertNotIn("clean-pkg: 2.0-1 -> 2.1-1", report)

    def test_update_report_reason_summary_is_deduplicated_and_capped(self) -> None:
        findings = [
            finding(rule_id, severity)
            for rule_id, severity in (
                ("source-domain-changed", Severity.HIGH),
                ("source-domain-changed", Severity.HIGH),
                ("checksum-skip-added", Severity.HIGH),
                ("curl-pipe-shell", Severity.HIGH),
                ("install-script", Severity.MEDIUM),
            )
        ]
        report = format_update_review(result(review("busy-pkg", findings=findings)))
        self.assertIn(
            "- busy-pkg: source domain changed, checksum SKIP added, remote download piped to shell, +1 more",
            report,
        )

    def test_update_report_keeps_note_only_package_details(self) -> None:
        report = format_update_review(result(review("note-pkg", notes=["No review baseline could be found."])))
        for text in ("No findings:", "- note-pkg", "Details:", "note-pkg: 1.0-1 -> 1.1-1", "note: No review baseline could be found."):
            self.assertIn(text, report)

    def test_incomplete_reports_preserve_safety_messages(self) -> None:
        update_report = format_update_review(
            result(review("broken-pkg", analysis_errors=["candidate metadata PKGBUILD: is not valid UTF-8"]))
        )
        for text in ("Incomplete analysis:", "warning: candidate metadata PKGBUILD", "Analysis incomplete.", "Existing review baselines were not changed."):
            self.assertIn(text, update_report)
        self.assertNotIn("No findings", update_report)

        refresh_report = format_update_review(
            result(
                review(
                    "broken-pkg",
                    analysis_errors=["candidate metadata PKGBUILD: cannot be read"],
                    refresh_blocked=True,
                ),
                cache_refresh=True,
            )
        )
        self.assertIn("Review baselines were not refreshed for incomplete analyses.", refresh_report)
        self.assertNotIn("baseline refresh --force", refresh_report)

    def test_update_report_verbose_still_includes_finding_details(self) -> None:
        report = format_update_review(
            result(
                review(
                    "verbose-pkg",
                    findings=[
                        finding(
                            "source-domain-changed",
                            Severity.HIGH,
                            old_value="https://old.example/app.tar.gz",
                            new_value="https://new.example/app.tar.gz",
                        )
                    ],
                )
            ),
            verbose=True,
        )
        for text in (
            "line: sha256sums=('SKIP')",
            "old: https://old.example/app.tar.gz",
            "new: https://new.example/app.tar.gz",
            "hint: review this finding",
        ):
            self.assertIn(text, report)

    def test_explain_modes_and_unknown_rules(self) -> None:
        known = finding("source-domain-changed", Severity.HIGH)
        unknown = Finding("unknown-rule", Severity.LOW, "unknown", 10, "test", "test")
        cases = (
            ("enabled", [known], {"explain": True}, 1, False),
            ("disabled", [known], {"explain": False}, 0, False),
            ("unknown-silent", [known, unknown], {"explain": True}, 1, False),
            ("with-verbose", [known], {"explain": True, "verbose": True}, 1, True),
        )
        for name, findings, options, explanation_count, verbose in cases:
            with self.subTest(name=name):
                report = format_findings(findings, **options)
                self.assertEqual(report.count("What:"), explanation_count)
                self.assertEqual("line:" in report and "hint:" in report, verbose)
                if explanation_count:
                    self.assertIn("Why:", report)
                    self.assertIn("Inspect:", report)

    def test_all_current_rule_ids_have_explanations(self) -> None:
        current_rule_ids = """
            eval-used curl-pipe-shell setuid-permission privilege-command install-script
            pacman-hook-exec shell-c source-command decoded-pipe-shell inline-interpreter-command
            scriptlet-package-manager direct-exec-package-manager network-in-build writes-outside-pkgdir
            checksum-skip source-url-added https-to-http-downgrade source-domain-changed
            checksum-array-removed checksum-algorithm-weakened checksum-count-mismatch checksum-skip-added
            install-script-added pacman-hook-added aur-metadata-executable-added aur-metadata-elf-added
            dependency-added javascript-tooling-dependency-added build-tool-dependency-added
            aur-dependency-added dependency-moved dependency-removed temporary-directory-package-install
            suspicious-live-install-sequence dependency-with-risk-signals
        """.split()
        for rule_id in current_rule_ids:
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, EXPLANATIONS, f"Missing explanation for {rule_id}")
