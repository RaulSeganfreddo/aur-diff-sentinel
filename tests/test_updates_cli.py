from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.cli import run
from aur_diff_sentinel.provider import AurUpdate, InstalledPackageStatus
from tests.helpers import SAMPLES, fixture_fetcher, write_metadata

class UpdatesCliTests(unittest.TestCase):
    def run_cli(self, argv: list[str], stdin_text: str = "") -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = run(argv, stdin=io.StringIO(stdin_text))
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
        self.assertIn("baseline status", stdout)
        self.assertIn("baseline prune", stdout)

    def test_baseline_help_mentions_status_command(self) -> None:
        exit_code, stdout, stderr = self.run_cli(["baseline", "--help"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("status", stdout)

    def test_updates_helper_error_returns_two(self) -> None:
        with patch("aur_diff_sentinel.cli.discover_updates", side_effect=RuntimeError("no helper")):
            exit_code, _stdout, stderr = self.run_cli(["updates"])

        self.assertEqual(exit_code, 2)
        self.assertIn("no helper", stderr)

    def test_updates_with_findings_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"))
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            (baseline / ".aur-sentinel-baseline-version").write_text("1.0-1", encoding="utf-8")

            with (
                patch("aur_diff_sentinel.cli.discover_updates", return_value=[update]),
                patch("aur_diff_sentinel.cli.AurCache", return_value=cache),
            ):
                exit_code, stdout, stderr = self.run_cli(["updates", "--cache-dir", str(root)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stderr, "")
            self.assertIn("High attention:", stdout)
            self.assertIn("checksum-skip-added", stdout)
            self.assertIn("No packages were updated.", stdout)
            self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_baseline_refresh_blocked_message_mentions_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"))
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )

            with (
                patch("aur_diff_sentinel.cli.discover_updates", return_value=[update]),
                patch("aur_diff_sentinel.cli.AurCache", return_value=cache),
                patch(
                    "aur_diff_sentinel.update_review.installed_version",
                    return_value="1.1-1",
                ),
            ):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "refresh", "--cache-dir", str(root)]
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stderr, "")
        self.assertIn("matching installed baselines were not refreshed", stdout)
        self.assertIn("baseline refresh --force", stdout)
        self.assertIn("No packages were updated.", stdout)

    def test_baseline_refresh_uses_cached_latest_when_no_updates_are_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

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
            self.assertIn("Review baselines refreshed: 1", stdout)
            self.assertEqual(cache.baseline_version("example-bin"), "1.1-1")

    def test_baseline_status_reports_no_cached_baselines(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            exit_code, stdout, stderr = self.run_cli(
                ["baseline", "status", "--cache-dir", temp_dir]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Cached baselines: 0", stdout)
        self.assertIn("No cached baselines found.", stdout)
        self.assertIn("No packages were updated.", stdout)
        self.assertNotIn("baseline refresh --force", stdout)
        self.assertNotIn("baseline prune", stdout)

    def test_baseline_status_groups_cached_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            write_metadata(cache.baseline_dir("current-pkg"), "current-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("current-pkg"), "current-pkg", "1.0", "1")
            write_metadata(cache.baseline_dir("ready-pkg"), "ready-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("ready-pkg"), "ready-pkg", "1.1", "1")
            write_metadata(cache.baseline_dir("pending-pkg"), "pending-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("pending-pkg"), "pending-pkg", "1.1", "1")
            write_metadata(cache.baseline_dir("unreviewed-pkg"), "unreviewed-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("unreviewed-pkg"), "unreviewed-pkg", "1.1", "1")
            write_metadata(cache.baseline_dir("missing-pkg"), "missing-pkg", "2.0", "1")
            write_metadata(cache.latest_dir("missing-pkg"), "missing-pkg", "2.0", "1")
            write_metadata(cache.baseline_dir("unknown-pkg"), "unknown-pkg", "3.0", "1")
            write_metadata(cache.latest_dir("unknown-pkg"), "unknown-pkg", "3.0", "1")
            incomplete_baseline = cache.baseline_dir("incomplete-pkg")
            incomplete_latest = cache.latest_dir("incomplete-pkg")
            incomplete_baseline.mkdir(parents=True)
            write_metadata(incomplete_latest, "incomplete-pkg", "4.0", "1")

            def status(package: str) -> InstalledPackageStatus:
                return {
                    "current-pkg": InstalledPackageStatus(package, version="1.0-1"),
                    "ready-pkg": InstalledPackageStatus(package, version="1.1-1"),
                    "pending-pkg": InstalledPackageStatus(package, version="1.0-1"),
                    "unreviewed-pkg": InstalledPackageStatus(package, version="1.2-1"),
                    "missing-pkg": InstalledPackageStatus(
                        package,
                        missing=True,
                        error="package was not found",
                    ),
                    "unknown-pkg": InstalledPackageStatus(
                        package,
                        error="pacman database error",
                    ),
                }[package]

            with patch("aur_diff_sentinel.baseline_status.query_installed_package", side_effect=status):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "status", "--cache-dir", str(root)]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Cached baselines: 7", stdout)
            self.assertIn("Current:", stdout)
            self.assertIn("- current-pkg: installed 1.0-1, baseline 1.0-1", stdout)
            self.assertIn("Ready to refresh:", stdout)
            self.assertIn(
                "- ready-pkg: installed 1.1-1, baseline 1.0-1, reviewed 1.1-1",
                stdout,
            )
            self.assertIn(
                "To refresh matching installed baselines, run: "
                "aur-diff-sentinel baseline refresh",
                stdout,
            )
            self.assertIn(
                "If reviewed findings are intentionally accepted, use: "
                "aur-diff-sentinel baseline refresh --force",
                stdout,
            )
            self.assertIn("Pending reviewed metadata:", stdout)
            self.assertIn(
                "- pending-pkg: installed 1.0-1, baseline 1.0-1, reviewed 1.1-1",
                stdout,
            )
            self.assertIn("Installed not reviewed:", stdout)
            self.assertIn(
                "- unreviewed-pkg: installed 1.2-1, baseline 1.0-1, reviewed 1.1-1",
                stdout,
            )
            self.assertIn("Not installed:", stdout)
            self.assertIn("- missing-pkg: baseline 2.0-1, reviewed 2.0-1", stdout)
            self.assertIn(
                "To remove sentinel cache for packages no longer installed, run: "
                "aur-diff-sentinel baseline prune",
                stdout,
            )
            self.assertIn("Unknown:", stdout)
            self.assertIn("- unknown-pkg: pacman database error", stdout)
            self.assertIn("Incomplete cache:", stdout)
            self.assertIn("- incomplete-pkg: baseline version could not be determined", stdout)
            self.assertIn("No packages were updated.", stdout)

    def test_baseline_status_omits_action_hints_without_actionable_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            write_metadata(cache.baseline_dir("current-pkg"), "current-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("current-pkg"), "current-pkg", "1.0", "1")
            write_metadata(cache.baseline_dir("unknown-pkg"), "unknown-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("unknown-pkg"), "unknown-pkg", "1.0", "1")

            def status(package: str) -> InstalledPackageStatus:
                if package == "current-pkg":
                    return InstalledPackageStatus(package, version="1.0-1")
                return InstalledPackageStatus(package, error="pacman database error")

            with patch(
                "aur_diff_sentinel.baseline_status.query_installed_package",
                side_effect=status,
            ):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "status", "--cache-dir", str(root)]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Current:", stdout)
            self.assertIn("Unknown:", stdout)
            self.assertNotIn("baseline refresh --force", stdout)
            self.assertNotIn("baseline prune", stdout)

    def test_baseline_prune_reports_no_missing_cached_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            write_metadata(cache.baseline_dir("installed-pkg"), "installed-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("installed-pkg"), "installed-pkg", "1.0", "1")

            with patch(
                "aur_diff_sentinel.baseline_prune.query_installed_package",
                return_value=InstalledPackageStatus("installed-pkg", version="1.0-1"),
            ):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "prune", "--cache-dir", str(root)]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("No cached reviewed packages are missing from the system.", stdout)
            self.assertIn("No packages were updated.", stdout)

    def test_baseline_prune_interactively_prunes_selected_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            for package in ("missing-a", "missing-b", "installed-pkg"):
                write_metadata(cache.baseline_dir(package), package, "1.0", "1")
                write_metadata(cache.latest_dir(package), package, "1.0", "1")

            def status(package: str) -> InstalledPackageStatus:
                if package == "installed-pkg":
                    return InstalledPackageStatus(package, version="1.0-1")
                return InstalledPackageStatus(package, missing=True, error="package was not found")

            with patch("aur_diff_sentinel.baseline_prune.query_installed_package", side_effect=status):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "prune", "--cache-dir", str(root)],
                    stdin_text="1\ny\n",
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Cached reviewed packages no longer installed:", stdout)
            self.assertIn("Pruned sentinel cache for packages no longer installed: 1", stdout)
            self.assertFalse(cache.baseline_dir("missing-a").exists())
            self.assertFalse(cache.latest_dir("missing-a").exists())
            self.assertTrue(cache.baseline_dir("missing-b").exists())
            self.assertTrue(cache.latest_dir("missing-b").exists())
            self.assertTrue(cache.baseline_dir("installed-pkg").exists())

    def test_baseline_prune_confirmation_no_prunes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            write_metadata(cache.baseline_dir("missing-pkg"), "missing-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("missing-pkg"), "missing-pkg", "1.0", "1")

            with patch(
                "aur_diff_sentinel.baseline_prune.query_installed_package",
                return_value=InstalledPackageStatus(
                    "missing-pkg",
                    missing=True,
                    error="package was not found",
                ),
            ):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "prune", "--cache-dir", str(root)],
                    stdin_text="all\nn\n",
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("No sentinel cache entries were pruned.", stdout)
            self.assertTrue(cache.baseline_dir("missing-pkg").exists())
            self.assertTrue(cache.latest_dir("missing-pkg").exists())

    def test_baseline_prune_all_prunes_all_missing_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            for package in ("missing-a", "missing-b", "installed-pkg"):
                write_metadata(cache.baseline_dir(package), package, "1.0", "1")
                write_metadata(cache.latest_dir(package), package, "1.0", "1")

            def status(package: str) -> InstalledPackageStatus:
                if package == "installed-pkg":
                    return InstalledPackageStatus(package, version="1.0-1")
                return InstalledPackageStatus(package, missing=True, error="package was not found")

            with patch("aur_diff_sentinel.baseline_prune.query_installed_package", side_effect=status):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "prune", "--all", "--cache-dir", str(root)]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Pruned sentinel cache for packages no longer installed: 2", stdout)
            self.assertFalse(cache.baseline_dir("missing-a").exists())
            self.assertFalse(cache.latest_dir("missing-a").exists())
            self.assertFalse(cache.baseline_dir("missing-b").exists())
            self.assertFalse(cache.latest_dir("missing-b").exists())
            self.assertTrue(cache.baseline_dir("installed-pkg").exists())

    def test_baseline_prune_reports_unknown_status_without_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            write_metadata(cache.baseline_dir("unknown-pkg"), "unknown-pkg", "1.0", "1")
            write_metadata(cache.latest_dir("unknown-pkg"), "unknown-pkg", "1.0", "1")

            with patch(
                "aur_diff_sentinel.baseline_prune.query_installed_package",
                return_value=InstalledPackageStatus(
                    "unknown-pkg",
                    error="pacman database error",
                ),
            ):
                exit_code, stdout, stderr = self.run_cli(
                    ["baseline", "prune", "--all", "--cache-dir", str(root)]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("could not be checked", stdout)
            self.assertIn("unknown-pkg: pacman database error", stdout)
            self.assertTrue(cache.baseline_dir("unknown-pkg").exists())
            self.assertTrue(cache.latest_dir("unknown-pkg").exists())
