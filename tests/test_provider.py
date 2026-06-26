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
    is_aur_package,
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

    def test_parse_update_output_accepts_valid_package_name_characters(self) -> None:
        updates = parse_update_output(
            "\n".join(
                [
                    "browser-example-bin 1.0-1 -> 1.1-1",
                    "lib32-example 1.0-1 -> 1.1-1",
                    "pkg+feature 1.0-1 -> 1.1-1",
                    "name@variant 1.0-1 -> 1.1-1",
                    "name..variant 1.0-1 -> 1.1-1",
                    "",
                ]
            )
        )

        self.assertEqual(
            [update.package for update in updates],
            [
                "browser-example-bin",
                "lib32-example",
                "pkg+feature",
                "name@variant",
                "name..variant",
            ],
        )

    def test_parse_update_output_rejects_invalid_package_names(self) -> None:
        for package in ("../evil", "/tmp/pkg", ".hidden", "-bad", "bad/name"):
            with self.subTest(package=package):
                with self.assertRaisesRegex(RuntimeError, "invalid AUR package name"):
                    parse_update_output(f"{package} 1.0-1 -> 1.1-1\n")

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

    def test_query_installed_package_distinguishes_missing_and_unknown_errors(self) -> None:
        def missing_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, "", "error: package 'example-bin' was not found")

        missing = query_installed_package("example-bin", runner=missing_runner)
        self.assertTrue(missing.missing)
        self.assertIsNone(missing.version)

        def unknown_runner(_command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 1, "", "pacman database error")

        unknown = query_installed_package("example-bin", runner=unknown_runner)
        self.assertFalse(unknown.missing)
        self.assertEqual(unknown.error, "pacman database error")

    def test_is_aur_package_git_suffix(self) -> None:
        self.assertTrue(is_aur_package("foo-git"))

    def test_is_aur_package_bin_suffix(self) -> None:
        self.assertTrue(is_aur_package("foo-bin"))

    def test_is_aur_package_svn_suffix(self) -> None:
        self.assertTrue(is_aur_package("foo-svn"))

    def test_is_aur_package_hg_suffix(self) -> None:
        self.assertTrue(is_aur_package("foo-hg"))

    def test_is_aur_package_bzr_suffix(self) -> None:
        self.assertTrue(is_aur_package("foo-bzr"))

    def test_is_aur_package_nightly_suffix(self) -> None:
        self.assertTrue(is_aur_package("foo-nightly"))

    def test_is_aur_package_beta_suffix(self) -> None:
        self.assertTrue(is_aur_package("foo-beta"))

    def test_is_aur_package_normal_name_found_in_repo(self) -> None:
        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 0, "Repository : extra\nName : bash\n", "")

        self.assertFalse(is_aur_package("bash", runner=runner))

    def test_is_aur_package_normal_name_not_in_repo(self) -> None:
        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, "", "error: package 'unknown' was not found")

        self.assertTrue(is_aur_package("unknown", runner=runner))

    def test_is_aur_package_normal_name_empty_stdout(self) -> None:
        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 0, "", "")

        self.assertFalse(is_aur_package("bash", runner=runner))

    def test_is_aur_package_pacman_oserror_fallback(self) -> None:
        def runner(_command: list[str]) -> subprocess.CompletedProcess[str]:
            raise OSError("pacman not found")

        self.assertFalse(is_aur_package("normal-pkg", runner=runner))

    def test_is_aur_package_heuristic_takes_priority(self) -> None:
        def runner(_command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "Repository : extra\nName : foo-git\n", "")

        self.assertTrue(is_aur_package("foo-git", runner=runner))


