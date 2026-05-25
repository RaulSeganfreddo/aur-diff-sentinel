from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from aur_diff_sentinel.cache import AurCache, metadata_version
from aur_diff_sentinel.cli import run
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.provider import AurUpdate, discover_updates, parse_update_output
from aur_diff_sentinel.report import format_findings, format_update_review
from aur_diff_sentinel.scanner import scan_diff_text, scan_text, source_lines_from_diff, source_lines_from_text
from aur_diff_sentinel.update_review import (
    PackageReview,
    UpdateReviewResult,
    refresh_cached_reviewed_baselines,
    review_updates,
)


SAMPLES = Path(__file__).parent / "samples"


def rule_ids(text: str) -> set[str]:
    return {finding.rule_id for finding in scan_text(text)}


class ScannerTests(unittest.TestCase):
    def test_eval_is_detected(self) -> None:
        self.assertIn("eval-used", rule_ids('eval "$flags"'))

    def test_curl_pipe_shell_is_detected(self) -> None:
        self.assertIn("curl-pipe-shell", rule_ids("curl https://example.com/install.sh | bash"))
        self.assertIn("curl-pipe-shell", rule_ids("wget -O- https://example.com/install.sh | sh"))

    def test_checksum_skip_is_detected(self) -> None:
        self.assertIn("checksum-skip", rule_ids("sha256sums=('SKIP')"))

    def test_setuid_permission_is_detected(self) -> None:
        self.assertIn("setuid-permission", rule_ids('chmod 4755 "$pkgdir/usr/bin/example"'))
        self.assertIn("setuid-permission", rule_ids('install -Dm4755 helper "$pkgdir/usr/bin/helper"'))

    def test_install_script_is_detected(self) -> None:
        self.assertIn("install-script", rule_ids("install=example.install"))

    def test_shell_c_is_detected(self) -> None:
        self.assertIn("shell-c", rule_ids('bash -c "$generated_command"'))
        self.assertIn("shell-c", rule_ids('sh -c "echo test"'))

    def test_source_command_is_detected(self) -> None:
        self.assertIn("source-command", rule_ids("source ./extra.sh"))
        self.assertIn("source-command", rule_ids(". ./extra.sh"))

    def test_obfuscated_command_is_detected(self) -> None:
        self.assertIn("obfuscated-command", rule_ids("base64 -d payload.txt | sh"))
        self.assertIn("obfuscated-command", rule_ids("python -c 'print(1)'"))

    def test_full_line_comments_are_ignored(self) -> None:
        self.assertEqual(scan_text("# eval \"$flags\"\n# curl https://example.com/file | bash"), [])

    def test_function_context_is_tracked(self) -> None:
        lines = source_lines_from_text(
            "\n".join(
                [
                    "pkgname=example",
                    "prepare() {",
                    "    curl https://example.com/file.tar.gz -o file.tar.gz",
                    "}",
                    "pkgver=1.0",
                    "function package {",
                    "    install -Dm755 example \"$pkgdir/usr/bin/example\"",
                    "}",
                    "pkgrel=1",
                ]
            )
        )

        self.assertEqual(lines[0].function_name, None)
        self.assertEqual(lines[1].function_name, "prepare")
        self.assertEqual(lines[2].function_name, "prepare")
        self.assertEqual(lines[3].function_name, "prepare")
        self.assertEqual(lines[4].function_name, None)
        self.assertEqual(lines[5].function_name, "package")
        self.assertEqual(lines[6].function_name, "package")
        self.assertEqual(lines[8].function_name, None)

    def test_network_in_build_is_detected_inside_build_functions(self) -> None:
        ids = rule_ids(
            "\n".join(
                [
                    "prepare() {",
                    "    curl https://example.com/file.tar.gz -o file.tar.gz",
                    "    git clone https://example.com/repo.git",
                    "    npm install",
                    "}",
                ]
            )
        )

        self.assertIn("network-in-build", ids)

    def test_network_in_build_ignores_top_level_sources(self) -> None:
        ids = rule_ids('source=("https://example.com/file.tar.gz")')

        self.assertNotIn("network-in-build", ids)

    def test_network_in_build_context_ends_after_function(self) -> None:
        ids = rule_ids(
            "\n".join(
                [
                    "prepare() {",
                    "    true",
                    "}",
                    "curl https://example.com/file.tar.gz -o file.tar.gz",
                ]
            )
        )

        self.assertNotIn("network-in-build", ids)

    def test_writes_outside_pkgdir_is_detected(self) -> None:
        ids = rule_ids(
            "\n".join(
                [
                    "package() {",
                    "    install -Dm755 example /usr/bin/example",
                    "}",
                ]
            )
        )

        self.assertIn("writes-outside-pkgdir", ids)

    def test_writes_outside_pkgdir_allows_pkgdir_paths(self) -> None:
        ids = rule_ids(
            "\n".join(
                [
                    "package() {",
                    "    install -Dm755 example \"$pkgdir/usr/bin/example\"",
                    "    install -Dm644 example.conf \"${pkgdir}/etc/example.conf\"",
                    "}",
                ]
            )
        )

        self.assertNotIn("writes-outside-pkgdir", ids)

    def test_clean_input_produces_no_findings(self) -> None:
        text = (SAMPLES / "clean.PKGBUILD").read_text(encoding="utf-8")
        self.assertEqual(scan_text(text), [])

    def test_multiple_findings_are_returned(self) -> None:
        text = (SAMPLES / "suspicious.PKGBUILD").read_text(encoding="utf-8")
        ids = [finding.rule_id for finding in scan_text(text)]

        self.assertIn("checksum-skip", ids)
        self.assertIn("eval-used", ids)
        self.assertIn("setuid-permission", ids)
        self.assertGreaterEqual(len(ids), 5)

    def test_diff_added_lines_are_scanned(self) -> None:
        text = (SAMPLES / "suspicious.diff").read_text(encoding="utf-8")
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertIn("checksum-skip-added", ids)
        self.assertIn("eval-used", ids)
        self.assertIn("setuid-permission", ids)

    def test_diff_metadata_is_ignored(self) -> None:
        text = "+++ b/PKGBUILD\n@@ -1 +1 @@\n+eval \"$flags\"\n"
        lines = source_lines_from_diff(text)

        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].line_number, 1)
        self.assertEqual(lines[0].target_line_number, 1)
        self.assertEqual(lines[0].diff_line_number, 3)
        self.assertEqual(lines[0].filename, "PKGBUILD")
        self.assertEqual(lines[0].change_type, "added")
        self.assertEqual(lines[0].content, 'eval "$flags"')

    def test_diff_target_line_numbers_are_tracked(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -10,3 +20,4 @@",
                " context_before",
                "-old_checksum",
                "+eval \"$flags\"",
                " context_after",
                "+chmod 4755 \"$pkgdir/usr/bin/example\"",
            ]
        )
        lines = source_lines_from_diff(text)

        self.assertEqual([line.line_number for line in lines], [21, 23])
        self.assertEqual([line.target_line_number for line in lines], [21, 23])
        self.assertEqual([line.diff_line_number for line in lines], [7, 9])
        self.assertEqual([line.filename for line in lines], ["PKGBUILD", "PKGBUILD"])

    def test_diff_multi_file_filenames_are_tracked(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                "+eval \"$flags\"",
                "diff --git a/example.install b/example.install",
                "--- a/example.install",
                "+++ b/example.install",
                "@@ -3 +3 @@",
                "+systemctl start example.service",
            ]
        )
        findings = scan_diff_text(text)

        self.assertEqual(
            [(finding.filename, finding.line_number, finding.rule_id) for finding in findings],
            [
                ("PKGBUILD", 1, "eval-used"),
                ("example.install", 3, "privilege-command"),
            ],
        )

    def test_diff_contextual_rule_uses_visible_function_context(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,3 +1,4 @@",
                " prepare() {",
                "+    curl https://example.com/file.tar.gz -o file.tar.gz",
                " }",
            ]
        )
        findings = scan_diff_text(text)

        self.assertIn("network-in-build", {finding.rule_id for finding in findings})
        self.assertEqual(findings[0].function_name, "prepare")

    def test_diff_contextual_rule_ignores_top_level_source_url(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                '+source=("https://example.com/file.tar.gz")',
            ]
        )
        findings = scan_diff_text(text)

        self.assertNotIn("network-in-build", {finding.rule_id for finding in findings})

    def test_diff_source_change_findings_are_detected(self) -> None:
        text = (SAMPLES / "source-change.diff").read_text(encoding="utf-8")
        findings = scan_diff_text(text)
        ids = {finding.rule_id for finding in findings}

        self.assertIn("https-to-http-downgrade", ids)
        self.assertIn("source-domain-changed", ids)
        self.assertIn("source-url-added", ids)
        self.assertIn("checksum-skip-added", ids)

    def test_diff_source_change_findings_keep_old_and_new_values(self) -> None:
        text = (SAMPLES / "source-change.diff").read_text(encoding="utf-8")
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "source-domain-changed"
        )

        self.assertEqual(
            finding.old_value,
            "https://github.com/example/app/archive/v1.0.tar.gz",
        )
        self.assertEqual(
            finding.new_value,
            "http://downloads.example.net/app/v1.0.tar.gz",
        )
        self.assertEqual(finding.filename, "PKGBUILD")
        self.assertEqual(finding.line_number, 3)

    def test_diff_source_comparison_ignores_non_pkgbuild_files(self) -> None:
        text = "\n".join(
            [
                "diff --git a/example.install b/example.install",
                "--- a/example.install",
                "+++ b/example.install",
                "@@ -1 +1 @@",
                '-source=("https://github.com/example/app.tar.gz")',
                '+source=("http://strange.example/app.tar.gz")',
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertNotIn("source-domain-changed", ids)
        self.assertNotIn("https-to-http-downgrade", ids)

    def test_diff_multiline_source_arrays_are_compared(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,5 +1,5 @@",
                " source=(",
                '-  "https://github.com/example/app.tar.gz"',
                '+  "https://mirror.example/app.tar.gz"',
                " )",
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertIn("source-domain-changed", ids)

    def test_diff_removed_checksum_array_is_detected(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,4 +1,3 @@",
                " pkgname=example",
                " source=(\"https://example.com/app.tar.gz\")",
                "-sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
                " package() {",
            ]
        )
        findings = scan_diff_text(text)

        self.assertIn("checksum-array-removed", {finding.rule_id for finding in findings})

    def test_diff_checksum_algorithm_weakening_is_detected(self) -> None:
        text = (SAMPLES / "checksum-change.diff").read_text(encoding="utf-8")
        findings = scan_diff_text(text)
        ids = {finding.rule_id for finding in findings}

        self.assertIn("checksum-algorithm-weakened", ids)
        self.assertNotIn("checksum-array-removed", ids)

    def test_diff_checksum_algorithm_strengthening_is_ignored(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,4 +1,4 @@",
                " pkgname=example",
                " source=(\"https://example.com/app.tar.gz\")",
                "-md5sums=('abcdef0123456789abcdef0123456789')",
                "+sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
            ]
        )
        findings = scan_diff_text(text)

        self.assertNotIn("checksum-algorithm-weakened", {finding.rule_id for finding in findings})

    def test_diff_checksum_count_mismatch_is_detected(self) -> None:
        text = (SAMPLES / "checksum-change.diff").read_text(encoding="utf-8")
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "checksum-count-mismatch"
        )

        self.assertEqual(finding.severity.value, "MEDIUM")
        self.assertEqual(finding.old_value, "2")
        self.assertEqual(finding.new_value, "1")

    def test_diff_checksum_count_mismatch_matches_arch_suffixes(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,7 +1,7 @@",
                " pkgname=example",
                " source=(\"https://example.com/common.tar.gz\")",
                " sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
                " source_x86_64=(\"https://example.com/bin.tar.gz\")",
                "-sha256sums_x86_64=('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')",
                "+sha256sums_x86_64=('SKIP')",
            ]
        )
        findings = scan_diff_text(text)

        self.assertNotIn("checksum-count-mismatch", {finding.rule_id for finding in findings})

    def test_diff_vcs_checksum_skip_is_medium_without_duplicate_high(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,4 +1,4 @@",
                " pkgname=example-git",
                " source=(\"git+https://example.com/app.git\")",
                "-sha256sums=('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')",
                "+sha256sums=('SKIP')",
            ]
        )
        findings = scan_diff_text(text)
        skip_findings = [finding for finding in findings if "checksum-skip" in finding.rule_id]

        self.assertEqual([finding.rule_id for finding in skip_findings], ["checksum-skip-added"])
        self.assertEqual(skip_findings[0].severity.value, "MEDIUM")

    def test_diff_non_vcs_checksum_skip_stays_high(self) -> None:
        text = (SAMPLES / "checksum-change.diff").read_text(encoding="utf-8")
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "checksum-skip-added"
        )

        self.assertEqual(finding.severity.value, "HIGH")


class CliTests(unittest.TestCase):
    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = run(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_cli_clean_file_returns_zero(self) -> None:
        exit_code, stdout, _stderr = self.run_cli([str(SAMPLES / "clean.PKGBUILD")])

        self.assertEqual(exit_code, 0)
        self.assertIn("Summary: HIGH 0, MEDIUM 0, LOW 0", stdout)
        self.assertIn("no obvious high-risk patterns", stdout.lower())

    def test_cli_suspicious_file_returns_one(self) -> None:
        exit_code, stdout, _stderr = self.run_cli([str(SAMPLES / "suspicious.PKGBUILD")])

        self.assertEqual(exit_code, 1)
        self.assertIn("HIGH\n", stdout)
        self.assertIn("MEDIUM\n", stdout)
        self.assertIn("checksum-skip", stdout)
        self.assertIn("Summary: HIGH", stdout)
        self.assertNotIn("hint:", stdout)
        self.assertNotIn("line:", stdout)

    def test_cli_missing_file_returns_two(self) -> None:
        exit_code, _stdout, stderr = self.run_cli([str(SAMPLES / "missing.PKGBUILD")])

        self.assertEqual(exit_code, 2)
        self.assertIn("cannot read", stderr)

    def test_cli_diff_mode_scans_added_lines(self) -> None:
        exit_code, stdout, _stderr = self.run_cli(["--diff", str(SAMPLES / "suspicious.diff")])

        self.assertEqual(exit_code, 1)
        self.assertIn("eval-used", stdout)
        self.assertIn("PKGBUILD:4", stdout)
        self.assertNotIn("+++ b/PKGBUILD", stdout)
        self.assertNotIn(str(SAMPLES / "suspicious.diff"), stdout)

    def test_cli_diff_mode_reports_source_comparison_findings(self) -> None:
        exit_code, stdout, _stderr = self.run_cli(["--diff", str(SAMPLES / "source-change.diff")])

        self.assertEqual(exit_code, 1)
        self.assertIn("https-to-http-downgrade", stdout)
        self.assertIn("source-domain-changed", stdout)
        self.assertIn("source-url-added", stdout)
        self.assertIn("checksum-skip-added", stdout)

    def test_cli_verbose_shows_lines_and_hints(self) -> None:
        exit_code, stdout, _stderr = self.run_cli(["--verbose", str(SAMPLES / "suspicious.PKGBUILD")])

        self.assertEqual(exit_code, 1)
        self.assertIn("line: sha256sums=('SKIP')", stdout)
        self.assertIn("hint: SKIP can be legitimate", stdout)

    def test_cli_module_execution_returns_zero_for_clean_file(self) -> None:
        project_root = Path(__file__).parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(project_root / "src")
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "aur_diff_sentinel.cli",
                str(SAMPLES / "clean.PKGBUILD"),
            ],
            check=False,
            cwd=project_root,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("no obvious high-risk patterns", result.stdout.lower())


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
        self.assertIn("hint: SKIP can be legitimate", report)

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

        self.assertIn("Review baselines refreshed from reviewed cache: 1", report)
        self.assertIn("example-bin: 1.0-1 -> 1.1-1", report)
        self.assertNotIn("Review baselines were refreshed from cached metadata.", report)
        self.assertIn("No packages were updated.", report)

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
                    "No reviewed cached metadata was ready to refresh.",
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


class ProviderTests(unittest.TestCase):
    def test_parse_update_output_handles_empty_output(self) -> None:
        self.assertEqual(parse_update_output(""), [])

    def test_parse_update_output_handles_arrow_format(self) -> None:
        updates = parse_update_output("example-bin 1.0-1 -> 1.1-1\nfoo-git 2-1 -> 3-1\n")

        self.assertEqual(
            updates,
            [
                AurUpdate("example-bin", "1.0-1", "1.1-1"),
                AurUpdate("foo-git", "2-1", "3-1"),
            ],
        )

    def test_discover_updates_uses_injected_runner(self) -> None:
        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            self.assertEqual(command, ["paru", "-Qua"])
            return subprocess.CompletedProcess(command, 0, "example-bin 1.0-1 -> 1.1-1\n", "")

        self.assertEqual(
            discover_updates("paru", runner=runner),
            [AurUpdate("example-bin", "1.0-1", "1.1-1")],
        )

    def test_discover_updates_reports_helper_error(self) -> None:
        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, "", "helper failed")

        with self.assertRaisesRegex(RuntimeError, "helper failed"):
            discover_updates("paru", runner=runner)

    def test_discover_updates_treats_empty_nonzero_output_as_no_updates(self) -> None:
        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, "", "")

        self.assertEqual(discover_updates("paru", runner=runner), [])


class UpdateWorkflowTests(unittest.TestCase):
    def test_metadata_version_reads_srcinfo_and_pkgbuild_shapes(self) -> None:
        self.assertEqual(metadata_version("pkgver = 1.0\npkgrel = 2\n"), "1.0-2")
        self.assertEqual(metadata_version("pkgver=1.0\npkgrel=2\n"), "1.0-2")

    def test_updates_do_not_advance_existing_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=_fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"))
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )

            result = review_updates([update], cache)

            self.assertTrue(result.has_findings)
            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_missing_baseline_scans_latest_without_initializing_to_latest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(
                Path(temp_dir),
                fetcher=_fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"),
            )

            result = review_updates([update], cache)

            self.assertTrue(result.has_findings)
            self.assertFalse(cache.has_baseline(update.package))
            self.assertIn("no update diff was reviewed", " ".join(result.reviews[0].notes).lower())

    def test_missing_baseline_is_reconstructed_from_installed_version_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            _run_git(repo, "init")
            _run_git(repo, "config", "user.email", "test@example.invalid")
            _run_git(repo, "config", "user.name", "Test User")
            (repo / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            _run_git(repo, "add", "PKGBUILD")
            _run_git(repo, "commit", "-m", "old")
            (repo / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.1\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            _run_git(repo, "commit", "-am", "new")

            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root / "cache", fetcher=_copy_repo_fetcher(repo))

            result = review_updates([update], cache)

            self.assertTrue(cache.has_baseline(update.package))
            self.assertIn(
                "pkgver=1.0",
                (cache.baseline_dir(update.package) / "PKGBUILD").read_text(encoding="utf-8"),
            )
            self.assertIn("Initialized review baseline", " ".join(result.reviews[0].notes))

    def test_refresh_baseline_is_blocked_when_findings_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=_fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"))
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )

            result = review_updates([update], cache, refresh_baseline=True)

            self.assertTrue(result.refresh_blocked)
            self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_force_refresh_updates_baseline_even_with_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=_fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"))
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )

            result = review_updates([update], cache, refresh_baseline=True, force=True)

            self.assertFalse(result.refresh_blocked)
            self.assertTrue(result.reviews[0].baseline_refreshed)
            self.assertIn("pkgver=1.1", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_cached_refresh_updates_baseline_when_installed_matches_latest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            _write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            _write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_cached_reviewed_baselines(
                cache,
                installed_version_getter=lambda package: "1.1-1",
            )

            self.assertTrue(result.cache_refresh)
            self.assertTrue(result.reviews[0].baseline_refreshed)
            self.assertEqual(cache.baseline_version("example-bin"), "1.1-1")
            self.assertIn(
                "pkgver=1.1",
                (cache.baseline_dir("example-bin") / "PKGBUILD").read_text(encoding="utf-8"),
            )

    def test_cached_refresh_skips_when_installed_does_not_match_latest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            _write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            _write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_cached_reviewed_baselines(
                cache,
                installed_version_getter=lambda package: "1.0-1",
            )

            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertEqual(cache.baseline_version("example-bin"), "1.0-1")
            self.assertIn("Review baseline was not refreshed.", result.reviews[0].notes)

    def test_cached_refresh_ignores_latest_without_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            _write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_cached_reviewed_baselines(
                cache,
                installed_version_getter=lambda package: "1.1-1",
            )

            self.assertEqual(result.reviews, [])

    def test_cached_refresh_skips_when_baseline_already_matches_latest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            _write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.1", "1")
            _write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_cached_reviewed_baselines(
                cache,
                installed_version_getter=lambda package: "1.1-1",
            )

            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertIn("already matches", result.reviews[0].notes[0])


class UpdatesCliTests(unittest.TestCase):
    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = run(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_updates_no_updates_returns_zero(self) -> None:
        with patch("aur_diff_sentinel.cli.discover_updates", return_value=[]):
            exit_code, stdout, stderr = self.run_cli(["updates"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("No AUR updates found.", stdout)
        self.assertIn("No packages were updated.", stdout)

    def test_updates_verbose_is_accepted(self) -> None:
        with patch("aur_diff_sentinel.cli.discover_updates", return_value=[]):
            exit_code, stdout, stderr = self.run_cli(["updates", "--verbose"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("No AUR updates found.", stdout)

    def test_updates_rejects_abbreviated_verbose_flag(self) -> None:
        exit_code, _stdout, stderr = self.run_cli(["updates", "--verbos"])

        self.assertEqual(exit_code, 2)
        self.assertIn("unrecognized arguments: --verbos", stderr)

    def test_update_typo_suggests_updates_command(self) -> None:
        exit_code, _stdout, stderr = self.run_cli(["update"])

        self.assertEqual(exit_code, 2)
        self.assertIn("unknown command 'update'; did you mean 'updates'?", stderr)

    def test_baseline_typo_suggests_baseline_command(self) -> None:
        exit_code, _stdout, stderr = self.run_cli(["baselinee"])

        self.assertEqual(exit_code, 2)
        self.assertIn("unknown command 'baselinee'; did you mean 'baseline'?", stderr)

    def test_missing_file_still_reports_cannot_read(self) -> None:
        exit_code, _stdout, stderr = self.run_cli([str(SAMPLES / "missing.PKGBUILD")])

        self.assertEqual(exit_code, 2)
        self.assertIn("cannot read", stderr)

    def test_top_level_help_mentions_update_commands(self) -> None:
        exit_code, stdout, stderr = self.run_cli(["--help"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("updates", stdout)
        self.assertIn("baseline refresh", stdout)

    def test_updates_helper_error_returns_two(self) -> None:
        with patch("aur_diff_sentinel.cli.discover_updates", side_effect=RuntimeError("no helper")):
            exit_code, _stdout, stderr = self.run_cli(["updates"])

        self.assertEqual(exit_code, 2)
        self.assertIn("no helper", stderr)

    def test_baseline_refresh_blocked_message_mentions_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=_fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"))
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )

            with (
                patch("aur_diff_sentinel.cli.discover_updates", return_value=[update]),
                patch("aur_diff_sentinel.cli.AurCache", return_value=cache),
            ):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "refresh", "--cache-dir", str(root)]
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stderr, "")
        self.assertIn("review baselines were not refreshed", stdout)
        self.assertIn("baseline refresh --force", stdout)
        self.assertIn("No packages were updated.", stdout)

    def test_baseline_refresh_uses_cached_latest_when_no_updates_are_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            _write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            _write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            with (
                patch("aur_diff_sentinel.cli.discover_updates", return_value=[]),
                patch("aur_diff_sentinel.cli.AurCache", return_value=cache),
                patch(
                    "aur_diff_sentinel.update_review.installed_version",
                    return_value="1.1-1",
                ),
            ):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "refresh", "--cache-dir", str(root)]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Review baselines refreshed from reviewed cache: 1", stdout)
            self.assertEqual(cache.baseline_version("example-bin"), "1.1-1")


def _fixture_fetcher(pkgver: str, pkgrel: str, extra_line: str):
    def fetcher(update: AurUpdate, target: Path) -> None:
        target.mkdir(parents=True)
        (target / "PKGBUILD").write_text(
            "\n".join(
                [
                    f"pkgname={update.package}",
                    f"pkgver={pkgver}",
                    f"pkgrel={pkgrel}",
                    extra_line,
                    "",
                ]
            ),
            encoding="utf-8",
        )

    return fetcher


def _write_metadata(root: Path, pkgname: str, pkgver: str, pkgrel: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "PKGBUILD").write_text(
        "\n".join(
            [
                f"pkgname={pkgname}",
                f"pkgver={pkgver}",
                f"pkgrel={pkgrel}",
                "sha256sums=('abc')",
                "",
            ]
        ),
        encoding="utf-8",
    )
    if root.parent.name == "baselines":
        (root / ".aur-sentinel-baseline-version").write_text(
            f"{pkgver}-{pkgrel}",
            encoding="utf-8",
        )


def _copy_repo_fetcher(source: Path):
    def fetcher(_update: AurUpdate, target: Path) -> None:
        shutil.copytree(source, target)

    return fetcher


def _run_git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
