from __future__ import annotations

import io
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from aur_diff_sentinel.cli import run
from aur_diff_sentinel.report import format_findings
from aur_diff_sentinel.scanner import scan_diff_text, scan_text, source_lines_from_diff, source_lines_from_text


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

        self.assertIn("checksum-skip", ids)
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


if __name__ == "__main__":
    unittest.main()
