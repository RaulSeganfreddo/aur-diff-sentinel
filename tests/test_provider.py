from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from aur_diff_sentinel.provider import (
    COMMAND_TIMEOUT_SECONDS,
    AurUpdate,
    default_runner,
    discover_updates,
    is_aur_package,
    parse_update_output,
    query_installed_package,
)


def completed(
    command: list[str],
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class ProviderTests(unittest.TestCase):
    def test_default_runner_uses_fixed_timeout(self) -> None:
        expected = completed(["git", "status"])
        with patch("aur_diff_sentinel.provider.subprocess.run", return_value=expected) as run:
            self.assertIs(default_runner(["git", "status"]), expected)
        run.assert_called_once_with(
            ["git", "status"],
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    def test_default_runner_reports_timeout_and_oserror(self) -> None:
        cases = (
            (
                "timeout",
                subprocess.TimeoutExpired(["git", "status"], COMMAND_TIMEOUT_SECONDS),
                "git timed out after 60 seconds",
            ),
            ("oserror", OSError("not installed"), "cannot run git: not installed"),
        )
        for name, error, message in cases:
            with self.subTest(name=name), patch(
                "aur_diff_sentinel.provider.subprocess.run",
                side_effect=error,
            ):
                with self.assertRaisesRegex(RuntimeError, message):
                    default_runner(["git", "status"])

    def test_parse_update_output_formats(self) -> None:
        cases = (
            ("empty", "", []),
            (
                "arrow",
                "example-bin 1.0-1 -> 1.1-1\nfoo-git 2-1 -> 3-1\n",
                [AurUpdate("example-bin", "1.0-1", "1.1-1"), AurUpdate("foo-git", "2-1", "3-1")],
            ),
        )
        for name, output, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(parse_update_output(output), expected)

    def test_parse_update_output_accepts_valid_package_name_characters(self) -> None:
        packages = ("browser-example-bin", "lib32-example", "pkg+feature", "name@variant", "name..variant")
        updates = parse_update_output(
            "\n".join(f"{package} 1.0-1 -> 1.1-1" for package in packages)
        )
        self.assertEqual([update.package for update in updates], list(packages))

    def test_parse_update_output_rejects_invalid_package_names(self) -> None:
        for package in ("../evil", "/tmp/pkg", ".hidden", "-bad", "bad/name"):
            with self.subTest(package=package), self.assertRaisesRegex(
                RuntimeError,
                "invalid AUR package name",
            ):
                parse_update_output(f"{package} 1.0-1 -> 1.1-1\n")

    def test_discover_updates_runner_outcomes(self) -> None:
        cases = (
            ("success", 0, "example-bin 1.0-1 -> 1.1-1\n", "", [AurUpdate("example-bin", "1.0-1", "1.1-1")]),
            ("empty-error", 1, "", "", []),
        )
        for name, code, stdout, stderr, expected in cases:
            with self.subTest(name=name):
                def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                    self.assertEqual(command, ["paru", "-Qua"])
                    return completed(command, code, stdout, stderr)

                self.assertEqual(discover_updates("paru", runner=runner), expected)

    def test_discover_updates_reports_helper_error(self) -> None:
        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            return completed(command, 1, stderr="helper failed")

        with self.assertRaisesRegex(RuntimeError, "helper failed"):
            discover_updates("paru", runner=runner)

    def test_query_installed_package_distinguishes_missing_and_unknown_errors(self) -> None:
        errors = (
            ("missing", "error: package 'example-bin' was not found", True),
            ("unknown", "pacman database error", False),
        )
        for name, error, missing in errors:
            with self.subTest(name=name):
                status = query_installed_package(
                    "example-bin",
                    runner=lambda command: completed(command, 1, stderr=error),
                )
                self.assertEqual(status.missing, missing)
                self.assertIsNone(status.version)
                if not missing:
                    self.assertEqual(status.error, error)

    def test_is_aur_package_suffix_heuristics(self) -> None:
        for suffix in ("git", "bin", "svn", "hg", "bzr", "nightly", "beta"):
            with self.subTest(suffix=suffix):
                self.assertTrue(is_aur_package(f"foo-{suffix}"))

    def test_is_aur_package_pacman_outcomes(self) -> None:
        cases = (
            ("found", 0, "Repository : extra\nName : bash\n", "", False),
            ("not-found", 1, "", "error: package 'unknown' was not found", True),
            ("empty-success", 0, "", "", False),
            ("unknown-error", 1, "", "pacman database error", False),
            ("missing-database", 1, "", "database file was not found", False),
        )
        for name, code, stdout, stderr, expected in cases:
            with self.subTest(name=name):
                runner = lambda command: completed(command, code, stdout, stderr)
                self.assertEqual(is_aur_package("unknown", runner=runner), expected)

    def test_is_aur_package_pacman_oserror_fallback(self) -> None:
        def runner(_command: list[str]) -> subprocess.CompletedProcess[str]:
            raise OSError("pacman not found")

        self.assertFalse(is_aur_package("normal-pkg", runner=runner))

    def test_is_aur_package_heuristic_takes_priority(self) -> None:
        def runner(_command: list[str]) -> subprocess.CompletedProcess[str]:
            return completed([], stdout="Repository : extra\nName : foo-git\n")

        self.assertTrue(is_aur_package("foo-git", runner=runner))
