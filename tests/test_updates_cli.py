from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.cli import run
from aur_diff_sentinel.provider import AurUpdate, InstalledPackageStatus
from tests.helpers import TempRootTestCase, reviewed_cache, write_cached_pair, write_metadata


class UpdatesCliTests(TempRootTestCase):
    def run_cli(self, argv: list[str], stdin_text: str = "") -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = run(argv, stdin=io.StringIO(stdin_text))
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def run_review(
        self,
        argv: list[str],
        cache: AurCache,
        updates: list[AurUpdate],
        *,
        installed: str | None = None,
    ) -> tuple[int, str, str]:
        patches = [
            patch("aur_diff_sentinel.cli.discover_updates", return_value=updates),
            patch("aur_diff_sentinel.cli.AurCache", return_value=cache),
        ]
        if installed is not None:
            patches.append(patch("aur_diff_sentinel.update_review.installed_version", return_value=installed))
        with self.enterContext(patches[0]), self.enterContext(patches[1]):
            if len(patches) == 3:
                with patches[2]:
                    return self.run_cli(argv)
            return self.run_cli(argv)

    def test_updates_no_updates_and_verbose_return_zero(self) -> None:
        for name, argv in (("default", ["updates"]), ("verbose", ["updates", "--verbose"])):
            with self.subTest(name=name), patch("aur_diff_sentinel.cli.discover_updates", return_value=[]):
                exit_code, stdout, stderr = self.run_cli(argv)
                self.assertEqual((exit_code, stderr), (0, ""))
                self.assertIn("No AUR updates found.", stdout)
                self.assertIn("No packages were updated.", stdout)

    def test_updates_rejects_abbreviated_verbose_flag(self) -> None:
        exit_code, _stdout, stderr = self.run_cli(["updates", "--verbos"])
        self.assertEqual(exit_code, 2)
        self.assertIn("unrecognized arguments: --verbos", stderr)

    def test_command_typos_are_suggested(self) -> None:
        cases = (
            ("update", "updates"),
            ("baselinee", "baseline"),
        )
        for value, suggestion in cases:
            with self.subTest(value=value):
                exit_code, _stdout, stderr = self.run_cli([value])
                self.assertEqual(exit_code, 2)
                self.assertIn(f"unknown command '{value}'; did you mean '{suggestion}'?", stderr)

    def test_help_mentions_update_commands_and_status(self) -> None:
        for name, argv, expected in (
            ("top-level", ["--help"], ("updates", "baseline refresh", "baseline status", "baseline prune")),
            ("baseline", ["baseline", "--help"], ("status",)),
        ):
            with self.subTest(name=name):
                exit_code, stdout, stderr = self.run_cli(argv)
                self.assertEqual((exit_code, stderr), (0, ""))
                for text in expected:
                    self.assertIn(text, stdout)

    def test_updates_helper_error_returns_two(self) -> None:
        with patch("aur_diff_sentinel.cli.discover_updates", side_effect=RuntimeError("no helper")):
            exit_code, _stdout, stderr = self.run_cli(["updates"])
        self.assertEqual(exit_code, 2)
        self.assertIn("no helper", stderr)

    def test_updates_with_findings_returns_one_and_keeps_baseline(self) -> None:
        update, cache = reviewed_cache(self.root, checksum="SKIP")
        baseline = cache.baseline_dir(update.package)
        exit_code, stdout, stderr = self.run_review(
            ["updates", "--cache-dir", str(self.root)],
            cache,
            [update],
        )
        self.assertEqual((exit_code, stderr), (1, ""))
        for text in ("High attention:", "checksum-skip-added", "No packages were updated."):
            self.assertIn(text, stdout)
        self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_updates_with_incomplete_analysis_returns_two(self) -> None:
        update = AurUpdate("example-bin", "1.0-1", "1.1-1")

        def fetcher(_update: AurUpdate, target) -> None:
            write_metadata(target, update.package, "1.1", "1")
            (target / "example.install").write_bytes(b"\xff")

        cache = AurCache(self.root, fetcher=fetcher)
        write_metadata(cache.baseline_dir(update.package), update.package, "1.0", "1")
        exit_code, stdout, stderr = self.run_review(["updates"], cache, [update])
        self.assertEqual((exit_code, stderr), (2, ""))
        self.assertIn("Analysis incomplete.", stdout)
        self.assertNotIn("No findings", stdout)

    def test_updates_fetch_failure_returns_two_after_reporting_complete_batch(self) -> None:
        updates = [
            AurUpdate("broken-pkg", "1.0-1", "1.1-1"),
            AurUpdate("reviewed-pkg", "2.0-1", "2.1-1"),
        ]
        cache = AurCache(self.root)
        write_metadata(cache.baseline_dir("broken-pkg"), "broken-pkg", "1.0", "1")
        write_metadata(cache.baseline_dir("reviewed-pkg"), "reviewed-pkg", "2.0", "1")

        def fetcher(update: AurUpdate, target) -> None:
            if update.package == "broken-pkg":
                raise RuntimeError("temporary fetch failure")
            write_metadata(target, update.package, "2.1", "1", checksum="SKIP")

        cache.fetcher = fetcher
        exit_code, stdout, stderr = self.run_review(["updates"], cache, updates)

        self.assertEqual((exit_code, stderr), (2, ""))
        for text in (
            "AUR updates found: 2",
            "broken-pkg: 1.0-1 -> 1.1-1",
            "candidate metadata fetch failed: temporary fetch failure",
            "reviewed-pkg: 2.0-1 -> 2.1-1",
            "checksum-skip-added",
            "No packages were updated.",
        ):
            self.assertIn(text, stdout)

    def test_baseline_refresh_blocked_message_mentions_force(self) -> None:
        update, cache = reviewed_cache(self.root, checksum="SKIP")
        exit_code, stdout, stderr = self.run_review(
            ["baseline", "refresh", "--cache-dir", str(self.root)],
            cache,
            [update],
            installed="1.1-1",
        )
        self.assertEqual((exit_code, stderr), (2, ""))
        self.assertIn("matching installed baselines were not refreshed", stdout)
        self.assertIn("baseline refresh --force", stdout)
        self.assertIn("No packages were updated.", stdout)

    def test_baseline_refresh_fetch_failure_returns_two_after_partial_refresh(self) -> None:
        updates = [
            AurUpdate("broken-pkg", "1.0-1", "1.1-1"),
            AurUpdate("complete-pkg", "1.0-1", "1.1-1"),
        ]
        cache = AurCache(self.root)
        for update in updates:
            write_cached_pair(cache, update.package, ("1.0", "1"), ("1.0", "1"))

        def fetcher(update: AurUpdate, target) -> None:
            if update.package == "broken-pkg":
                raise RuntimeError("temporary fetch failure")
            write_metadata(target, update.package, "1.1", "1")

        cache.fetcher = fetcher
        exit_code, stdout, stderr = self.run_review(
            ["baseline", "refresh", "--force"],
            cache,
            updates,
            installed="1.1-1",
        )

        self.assertEqual((exit_code, stderr), (2, ""))
        self.assertIn("Review baselines refreshed: 1", stdout)
        self.assertIn("candidate metadata fetch failed: temporary fetch failure", stdout)
        self.assertIn("complete-pkg: 1.0-1 -> 1.1-1", stdout)
        self.assertEqual(cache.baseline_version("broken-pkg"), "1.0-1")
        self.assertEqual(cache.baseline_version("complete-pkg"), "1.1-1")

    def test_baseline_refresh_uses_cached_latest_without_pending_updates(self) -> None:
        cache = AurCache(self.root)
        write_cached_pair(cache, "example-bin", ("1.0", "1"), ("1.1", "1"))
        exit_code, stdout, stderr = self.run_review(
            ["baseline", "refresh", "--cache-dir", str(self.root)],
            cache,
            [],
            installed="1.1-1",
        )
        self.assertEqual((exit_code, stderr), (0, ""))
        self.assertIn("Review baselines refreshed: 1", stdout)
        self.assertEqual(cache.baseline_version("example-bin"), "1.1-1")

    def test_baseline_status_reports_no_cached_baselines(self) -> None:
        exit_code, stdout, stderr = self.run_cli(["baseline", "status", "--cache-dir", str(self.root)])
        self.assertEqual((exit_code, stderr), (0, ""))
        for text in ("Cached baselines: 0", "No cached baselines found.", "No packages were updated."):
            self.assertIn(text, stdout)
        self.assertNotIn("baseline refresh --force", stdout)
        self.assertNotIn("baseline prune", stdout)

    def test_baseline_status_groups_cached_packages(self) -> None:
        cache = AurCache(self.root)
        package_versions = {
            "current-pkg": (("1.0", "1"), ("1.0", "1")),
            "ready-pkg": (("1.0", "1"), ("1.1", "1")),
            "pending-pkg": (("1.0", "1"), ("1.1", "1")),
            "unreviewed-pkg": (("1.0", "1"), ("1.1", "1")),
            "missing-pkg": (("2.0", "1"), ("2.0", "1")),
            "unknown-pkg": (("3.0", "1"), ("3.0", "1")),
        }
        for package, versions in package_versions.items():
            write_cached_pair(cache, package, *versions)
        (cache.baseline_dir("incomplete-pkg")).mkdir(parents=True)
        write_metadata(cache.latest_dir("incomplete-pkg"), "incomplete-pkg", "4.0", "1")

        statuses = {
            "current-pkg": InstalledPackageStatus("current-pkg", version="1.0-1"),
            "ready-pkg": InstalledPackageStatus("ready-pkg", version="1.1-1"),
            "pending-pkg": InstalledPackageStatus("pending-pkg", version="1.0-1"),
            "unreviewed-pkg": InstalledPackageStatus("unreviewed-pkg", version="1.2-1"),
            "missing-pkg": InstalledPackageStatus("missing-pkg", missing=True, error="package was not found"),
            "unknown-pkg": InstalledPackageStatus("unknown-pkg", error="pacman database error"),
        }
        with patch("aur_diff_sentinel.baseline_status.query_installed_package", side_effect=statuses.__getitem__):
            exit_code, stdout, stderr = self.run_cli(["baseline", "status", "--cache-dir", str(self.root)])
        self.assertEqual((exit_code, stderr), (0, ""))
        for text in (
            "Cached baselines: 7",
            "Current:",
            "- current-pkg: installed 1.0-1, baseline 1.0-1",
            "Ready to refresh:",
            "- ready-pkg: installed 1.1-1, baseline 1.0-1, reviewed 1.1-1",
            "aur-diff-sentinel baseline refresh --force",
            "Pending reviewed metadata:",
            "- pending-pkg: installed 1.0-1, baseline 1.0-1, reviewed 1.1-1",
            "Installed not reviewed:",
            "- unreviewed-pkg: installed 1.2-1, baseline 1.0-1, reviewed 1.1-1",
            "Not installed:",
            "- missing-pkg: baseline 2.0-1, reviewed 2.0-1",
            "aur-diff-sentinel baseline prune",
            "Unknown:",
            "- unknown-pkg: pacman database error",
            "Incomplete cache:",
            "- incomplete-pkg: baseline version could not be determined",
            "No packages were updated.",
        ):
            self.assertIn(text, stdout)

    def test_baseline_status_omits_hints_without_actionable_groups(self) -> None:
        cache = AurCache(self.root)
        for package in ("current-pkg", "unknown-pkg"):
            write_cached_pair(cache, package, ("1.0", "1"), ("1.0", "1"))
        statuses = {
            "current-pkg": InstalledPackageStatus("current-pkg", version="1.0-1"),
            "unknown-pkg": InstalledPackageStatus("unknown-pkg", error="pacman database error"),
        }
        with patch("aur_diff_sentinel.baseline_status.query_installed_package", side_effect=statuses.__getitem__):
            exit_code, stdout, stderr = self.run_cli(["baseline", "status", "--cache-dir", str(self.root)])
        self.assertEqual((exit_code, stderr), (0, ""))
        self.assertIn("Current:", stdout)
        self.assertIn("Unknown:", stdout)
        self.assertNotIn("baseline refresh --force", stdout)
        self.assertNotIn("baseline prune", stdout)

    @staticmethod
    def package_status(package: str) -> InstalledPackageStatus:
        if package == "installed-pkg":
            return InstalledPackageStatus(package, version="1.0-1")
        return InstalledPackageStatus(package, missing=True, error="package was not found")

    def seed_prune_packages(self, *packages: str) -> AurCache:
        cache = AurCache(self.root)
        for package in packages:
            write_cached_pair(cache, package, ("1.0", "1"), ("1.0", "1"))
        return cache

    def test_baseline_prune_reports_no_missing_cached_packages(self) -> None:
        self.seed_prune_packages("installed-pkg")
        with patch("aur_diff_sentinel.baseline_prune.query_installed_package", side_effect=self.package_status):
            exit_code, stdout, stderr = self.run_cli(["baseline", "prune", "--cache-dir", str(self.root)])
        self.assertEqual((exit_code, stderr), (0, ""))
        self.assertIn("No cached reviewed packages are missing from the system.", stdout)
        self.assertIn("No packages were updated.", stdout)

    def test_baseline_prune_selection_confirmation_and_all(self) -> None:
        cases = (
            ("selected", [], "1\ny\n", {"missing-a"}, 1),
            ("declined", [], "all\nn\n", set(), 0),
            ("all", ["--all"], "", {"missing-a", "missing-b"}, 2),
        )
        for name, options, stdin, removed, count in cases:
            with self.subTest(name=name):
                root = self.root / name
                cache = AurCache(root)
                for package in ("missing-a", "missing-b", "installed-pkg"):
                    write_cached_pair(cache, package, ("1.0", "1"), ("1.0", "1"))
                with patch("aur_diff_sentinel.baseline_prune.query_installed_package", side_effect=self.package_status):
                    exit_code, stdout, stderr = self.run_cli(
                        ["baseline", "prune", *options, "--cache-dir", str(root)],
                        stdin_text=stdin,
                    )
                self.assertEqual((exit_code, stderr), (0, ""))
                if count:
                    self.assertIn(f"Pruned sentinel cache for packages no longer installed: {count}", stdout)
                else:
                    self.assertIn("No sentinel cache entries were pruned.", stdout)
                for package in ("missing-a", "missing-b"):
                    self.assertEqual(cache.baseline_dir(package).exists(), package not in removed)
                self.assertTrue(cache.baseline_dir("installed-pkg").exists())

    def test_baseline_prune_reports_unknown_status_without_pruning(self) -> None:
        cache = self.seed_prune_packages("unknown-pkg")
        status = InstalledPackageStatus("unknown-pkg", error="pacman database error")
        with patch("aur_diff_sentinel.baseline_prune.query_installed_package", return_value=status):
            exit_code, stdout, stderr = self.run_cli(
                ["baseline", "prune", "--all", "--cache-dir", str(self.root)]
            )
        self.assertEqual((exit_code, stderr), (0, ""))
        self.assertIn("could not be checked", stdout)
        self.assertIn("unknown-pkg: pacman database error", stdout)
        self.assertTrue(cache.baseline_dir("unknown-pkg").exists())
        self.assertTrue(cache.latest_dir("unknown-pkg").exists())
