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

class BaselinePruneTests(unittest.TestCase):
    def test_parse_prune_selection_accepts_numbers_ranges_all_and_none(self) -> None:
        self.assertEqual(parse_prune_selection("1", 3), [0])
        self.assertEqual(parse_prune_selection("1,3", 3), [0, 2])
        self.assertEqual(parse_prune_selection("1-3", 3), [0, 1, 2])
        self.assertEqual(parse_prune_selection("1,2-3", 3), [0, 1, 2])
        self.assertEqual(parse_prune_selection("all", 3), [0, 1, 2])
        self.assertEqual(parse_prune_selection("none", 3), [])
        self.assertEqual(parse_prune_selection("", 3), [])

    def test_parse_prune_selection_rejects_invalid_values(self) -> None:
        for value in ("0", "4", "2-1", "abc", "1,,2"):
            with self.subTest(value=value):
                with self.assertRaises(SelectionError):
                    parse_prune_selection(value, 3)

    def test_prune_package_removes_latest_and_baseline_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            cache.prune_package("example-bin")

            self.assertFalse(cache.baseline_dir("example-bin").exists())
            self.assertFalse(cache.latest_dir("example-bin").exists())

    def test_prune_package_rejects_invalid_package_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))

            with self.assertRaisesRegex(RuntimeError, "invalid AUR package name"):
                cache.prune_package("../example-bin")


