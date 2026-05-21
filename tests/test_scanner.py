from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from aur_diff_sentinel.cli import run
from aur_diff_sentinel.scanner import scan_diff_text, scan_text, source_lines_from_diff


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
        self.assertIn("no obvious high-risk patterns", stdout.lower())

    def test_cli_suspicious_file_returns_one(self) -> None:
        exit_code, stdout, _stderr = self.run_cli([str(SAMPLES / "suspicious.PKGBUILD")])

        self.assertEqual(exit_code, 1)
        self.assertIn("checksum-skip", stdout)
        self.assertIn("Summary:", stdout)

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


if __name__ == "__main__":
    unittest.main()
