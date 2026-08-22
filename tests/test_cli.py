from __future__ import annotations

import io
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from unittest.mock import patch

from aur_diff_sentinel.cli import run
from tests.helpers import SAMPLES

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

    def test_top_level_version_uses_installed_distribution_metadata(self) -> None:
        with patch("aur_diff_sentinel.cli.distribution_version", return_value="0.13.2") as metadata_version:
            exit_code, stdout, stderr = self.run_cli(["--version"])

        self.assertEqual((exit_code, stdout, stderr), (0, "aur-diff-sentinel 0.13.2\n", ""))
        metadata_version.assert_called_once_with("aur-diff-sentinel")

    def test_top_level_version_falls_back_to_unknown_without_distribution(self) -> None:
        with patch(
            "aur_diff_sentinel.cli.distribution_version",
            side_effect=PackageNotFoundError("aur-diff-sentinel"),
        ):
            exit_code, stdout, stderr = self.run_cli(["--version"])

        self.assertEqual((exit_code, stdout, stderr), (0, "aur-diff-sentinel unknown\n", ""))

    def test_version_is_rejected_after_commands(self) -> None:
        for argv in (["updates", "--version"], ["baseline", "--version"]):
            with self.subTest(argv=argv):
                exit_code, _stdout, stderr = self.run_cli(argv)
                self.assertEqual(exit_code, 2)
                self.assertIn("--version", stderr)

    def test_top_level_help_mentions_version(self) -> None:
        exit_code, stdout, stderr = self.run_cli(["--help"])

        self.assertEqual((exit_code, stderr), (0, ""))
        self.assertIn("--version", stdout)

    def test_cli_verbose_shows_lines_and_hints(self) -> None:
        exit_code, stdout, _stderr = self.run_cli(["--verbose", str(SAMPLES / "suspicious.PKGBUILD")])

        self.assertEqual(exit_code, 1)
        self.assertIn("line: sha256sums=('SKIP')", stdout)
        self.assertIn("hint: SKIP skips source verification", stdout)

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
