from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from aur_diff_sentinel.cache import MAX_METADATA_SCAN_BYTES, AurCache, metadata_version, unified_diff_dirs
from aur_diff_sentinel.provider import AurUpdate
from aur_diff_sentinel.report import format_update_review
from aur_diff_sentinel.scanner import scan_diff_text
from aur_diff_sentinel.update_review import refresh_reviewed_baselines, review_updates
from tests.helpers import (
    TempRootTestCase,
    copy_repo_fetcher,
    fixture_fetcher,
    reviewed_cache,
    run_git,
    write_cached_pair,
    write_metadata,
)


class UpdateWorkflowTests(TempRootTestCase):
    def diff_dirs(self, name: str) -> tuple[Path, Path]:
        old_dir, new_dir = self.root / name / "old", self.root / name / "new"
        old_dir.mkdir(parents=True)
        new_dir.mkdir(parents=True)
        return old_dir, new_dir

    def test_metadata_version_reads_srcinfo_and_pkgbuild_shapes(self) -> None:
        cases = (
            ("spaced", "pkgver = 1.0\npkgrel = 2\n", "1.0-2"),
            ("compact", "pkgver=1.0\npkgrel=2\n", "1.0-2"),
            ("epoch", "epoch = 2\npkgver = 1.0\npkgrel = 2\n", "2:1.0-2"),
            ("quoted-epoch", "epoch='2'\npkgver=1.0\npkgrel=2\n", "2:1.0-2"),
            ("zero-epoch", "epoch=0\npkgver=1.0\npkgrel=2\n", "1.0-2"),
            ("dynamic-epoch", "epoch=$epoch\npkgver=1.0\npkgrel=2\n", None),
        )
        for name, text, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(metadata_version(text), expected)

    def test_fetch_latest_rejects_invalid_package_before_fetcher_runs(self) -> None:
        called = False

        def fetcher(_update: AurUpdate, _target: Path) -> None:
            nonlocal called
            called = True

        cache = AurCache(self.root, fetcher=fetcher)
        with self.assertRaisesRegex(RuntimeError, "invalid AUR package name"):
            cache.fetch_latest(AurUpdate("../evil", "1.0-1", "1.1-1"))
        self.assertFalse(called)
        self.assertFalse((self.root / "latest").exists())

    def test_refresh_baseline_rejects_invalid_package_before_replacing_baseline(self) -> None:
        cache = AurCache(self.root)
        write_cached_pair(cache, "example-bin", ("1.0", "1"), ("1.1", "1"))
        with self.assertRaisesRegex(RuntimeError, "invalid AUR package name"):
            cache.refresh_baseline(
                AurUpdate("../example-bin", "1.0-1", "1.1-1"),
                cache.latest_dir("example-bin"),
            )
        self.assertEqual(cache.baseline_version("example-bin"), "1.0-1")

    def test_reviewed_cached_packages_ignores_invalid_cache_directory_names(self) -> None:
        cache = AurCache(self.root)
        write_cached_pair(cache, "example-bin", ("1.0", "1"), ("1.1", "1"))
        write_metadata(self.root / "baselines" / ".hidden", ".hidden", "1.0", "1")
        write_metadata(self.root / "latest" / ".hidden", ".hidden", "1.1", "1")
        self.assertEqual(cache.reviewed_cached_packages(), ["example-bin"])

    def test_cache_path_guard_refuses_symlink_escape_before_delete(self) -> None:
        root, outside = self.root / "cache", self.root / "outside"
        outside_package = outside / "example-bin"
        outside_package.mkdir(parents=True)
        (outside_package / "PKGBUILD").write_text("pkgname=example-bin\n", encoding="utf-8")
        root.mkdir()
        (root / "latest").symlink_to(outside, target_is_directory=True)
        cache = AurCache(root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('abc')"))
        with self.assertRaisesRegex(RuntimeError, "outside cache directory"):
            cache.fetch_latest(AurUpdate("example-bin", "1.0-1", "1.1-1"))
        self.assertTrue(outside_package.exists())
        self.assertTrue((outside_package / "PKGBUILD").exists())

    def test_updates_do_not_advance_existing_baseline(self) -> None:
        update, cache = reviewed_cache(self.root, checksum="SKIP")
        baseline = cache.baseline_dir(update.package)
        result = review_updates([update], cache)
        self.assertTrue(result.has_findings)
        self.assertFalse(result.reviews[0].baseline_refreshed)
        self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_cache_diff_uses_dev_null_for_added_metadata_files(self) -> None:
        old_dir, new_dir = self.diff_dirs("dev-null")
        (new_dir / "example.install").write_text("post_install() {\n    echo done\n}\n", encoding="utf-8")
        diff_text, errors = unified_diff_dirs(old_dir, new_dir)
        self.assertEqual(errors, [])
        self.assertIn("--- /dev/null", diff_text)
        self.assertIn("+++ b/example.install", diff_text)
        self.assertIn("install-script-added", {finding.rule_id for finding in scan_diff_text(diff_text)})

    def test_cache_diff_added_hook_and_shell_files_are_detected(self) -> None:
        cases = (
            (
                "hook",
                "example.hook",
                "[Action]\nExec = /bin/sh -c 'npm install package'\n",
                {"pacman-hook-added", "scriptlet-package-manager"},
            ),
            ("shell", "helper", "#!/bin/sh\necho done\n", {"aur-metadata-executable-added"}),
        )
        for name, filename, content, expected in cases:
            with self.subTest(name=name):
                old_dir, new_dir = self.diff_dirs(name)
                (new_dir / filename).write_text(content, encoding="utf-8")
                diff_text, errors = unified_diff_dirs(old_dir, new_dir)
                self.assertEqual(errors, [])
                self.assertTrue(expected <= {finding.rule_id for finding in scan_diff_text(diff_text)})

    def test_cache_diff_reports_invalid_utf8_and_keeps_valid_file_diff(self) -> None:
        old_dir, new_dir = self.diff_dirs("invalid-utf8")
        (old_dir / "PKGBUILD").write_text("sha256sums=('abc')\n", encoding="utf-8")
        (new_dir / "PKGBUILD").write_text("sha256sums=('SKIP')\n", encoding="utf-8")
        (new_dir / "example.install").write_bytes(b"\xff\xfe")
        diff_text, errors = unified_diff_dirs(old_dir, new_dir)
        self.assertIn("sha256sums=('SKIP')", diff_text)
        self.assertIn("checksum-skip-added", {finding.rule_id for finding in scan_diff_text(diff_text)})
        self.assertEqual(errors, ["candidate metadata example.install: is not valid UTF-8"])

    def test_cache_diff_reports_symlink_and_oversized_metadata(self) -> None:
        old_dir, new_dir = self.diff_dirs("bounded")
        (new_dir / "large.install").write_text("x" * (MAX_METADATA_SCAN_BYTES + 1), encoding="utf-8")
        (new_dir / "linked.install").symlink_to(new_dir / "missing.install")
        diff_text, errors = unified_diff_dirs(old_dir, new_dir)
        self.assertEqual(diff_text, "")
        self.assertIn("exceeds the 524288-byte scan limit", errors[0])
        self.assertIn("symbolic links are not analyzed", errors[1])

    def test_cache_diff_reports_read_errors(self) -> None:
        old_dir, new_dir = self.diff_dirs("read-error")
        (new_dir / "PKGBUILD").write_text("pkgname=example\n", encoding="utf-8")
        with patch.object(Path, "read_text", side_effect=OSError("denied")):
            diff_text, errors = unified_diff_dirs(old_dir, new_dir)
        self.assertEqual(diff_text, "")
        self.assertEqual(errors, ["candidate metadata PKGBUILD: cannot be read: denied"])

    def test_cache_diff_reports_unreadable_baseline_metadata(self) -> None:
        old_dir, new_dir = self.diff_dirs("bad-baseline")
        (old_dir / "PKGBUILD").write_bytes(b"\xff")
        (new_dir / "PKGBUILD").write_text("pkgname=example\n", encoding="utf-8")
        diff_text, errors = unified_diff_dirs(old_dir, new_dir)
        self.assertEqual(diff_text, "")
        self.assertEqual(errors, ["baseline metadata PKGBUILD: is not valid UTF-8"])

    def test_updates_detects_added_elf_metadata_file(self) -> None:
        update, cache = reviewed_cache(self.root)

        def fetcher(_update: AurUpdate, target: Path) -> None:
            write_metadata(target, "example-bin", "1.1", "1", checksum=None)
            (target / "payload").write_bytes(b"\x7fELF\xff\x00")

        cache.fetcher = fetcher
        result = review_updates([update], cache)
        self.assertIn("aur-metadata-elf-added", {finding.rule_id for finding in result.findings})

    def test_updates_without_baseline_report_oversized_pkgbuild(self) -> None:
        def fetcher(_update: AurUpdate, target: Path) -> None:
            target.mkdir(parents=True)
            (target / "PKGBUILD").write_text("x" * (MAX_METADATA_SCAN_BYTES + 1), encoding="utf-8")

        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, "", "not found")

        result = review_updates(
            [AurUpdate("example-bin", "1.0-1", "1.1-1")],
            AurCache(self.root, fetcher=fetcher, runner=runner),
        )
        self.assertTrue(result.analysis_incomplete)
        self.assertFalse(result.has_findings)
        self.assertIn("exceeds the 524288-byte scan limit", result.reviews[0].analysis_errors[0])

    def test_update_batch_continues_after_incomplete_package(self) -> None:
        updates = [
            AurUpdate("broken-pkg", "1.0-1", "1.1-1"),
            AurUpdate("complete-pkg", "1.0-1", "1.1-1"),
        ]
        cache = AurCache(self.root)
        for update in updates:
            write_metadata(cache.baseline_dir(update.package), update.package, "1.0", "1")

        def fetcher(update: AurUpdate, target: Path) -> None:
            write_metadata(target, update.package, "1.1", "1")
            if update.package == "broken-pkg":
                (target / "broken.install").write_bytes(b"\xff")

        cache.fetcher = fetcher
        result = review_updates(updates, cache, aur_package_checker=lambda package: False)
        self.assertEqual(len(result.reviews), 2)
        self.assertTrue(result.reviews[0].analysis_errors)
        self.assertEqual(result.reviews[1].analysis_errors, [])

    def test_updates_review_path_reports_bun_install_sequence_and_keeps_baseline(self) -> None:
        update = AurUpdate("example-bin", "1.0-1", "1.1-1")
        cache = AurCache(self.root)
        baseline = cache.baseline_dir(update.package)
        write_metadata(baseline, update.package, "1.0", "1", checksum=None, extra_lines=("depends=(pencil)",))

        def fetcher(_update: AurUpdate, target: Path) -> None:
            write_metadata(
                target,
                "example-bin",
                "1.1",
                "1",
                checksum=None,
                extra_lines=("depends=(pencil bun)", "install=example-deps.install"),
            )
            (target / ".SRCINFO").write_text(
                "pkgbase = example-bin\n\tdepends = pencil\n\tdepends = bun\n",
                encoding="utf-8",
            )
            (target / "example-deps.install").write_text(
                "post_install() {\n    cd /tmp\n    bun add lodash js-digest\n}\n",
                encoding="utf-8",
            )

        cache.fetcher = fetcher
        result = review_updates([update], cache)
        ids = {finding.rule_id for finding in result.findings}
        self.assertTrue(
            {
                "install-script",
                "install-script-added",
                "javascript-tooling-dependency-added",
                "scriptlet-package-manager",
                "temporary-directory-package-install",
                "suspicious-live-install-sequence",
            }
            <= ids
        )
        self.assertIn("High attention:", format_update_review(result))
        self.assertFalse(result.reviews[0].baseline_refreshed)
        self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_update_review_caches_injected_aur_checker_per_batch(self) -> None:
        update = AurUpdate("example-bin", "1.0-1", "1.1-1")
        cache = AurCache(self.root)
        write_metadata(
            cache.baseline_dir(update.package),
            update.package,
            "1.0",
            "1",
            checksum=None,
            extra_lines=("depends=()",),
        )

        def fetcher(_update: AurUpdate, target: Path) -> None:
            write_metadata(
                target,
                "example-bin",
                "1.1",
                "1",
                checksum=None,
                extra_lines=("depends=(custom-lib)",),
            )
            (target / ".SRCINFO").write_text("pkgbase = example-bin\n\tdepends = custom-lib\n", encoding="utf-8")

        checked: list[str] = []

        def checker(package: str) -> bool:
            checked.append(package)
            return True

        cache.fetcher = fetcher
        result = review_updates([update], cache, aur_package_checker=checker)
        self.assertEqual(checked, ["custom-lib"])
        self.assertIn("aur-dependency-added", {finding.rule_id for finding in result.findings})

    def test_missing_baseline_scans_latest_without_initializing_to_latest(self) -> None:
        update = AurUpdate("example-bin", "1.0-1", "1.1-1")
        cache = AurCache(self.root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"))
        result = review_updates([update], cache)
        self.assertTrue(result.has_findings)
        self.assertFalse(cache.has_baseline(update.package))
        self.assertIn("no update diff was reviewed", " ".join(result.reviews[0].notes).lower())

    def test_missing_baseline_scans_hook_and_custom_install_files(self) -> None:
        cases = (
            (
                "hook",
                "example.hook",
                "[Action]\nExec = /bin/sh -c 'cd /tmp && npm install atomic-lockfile'\n",
                (),
                {"pacman-hook-exec", "scriptlet-package-manager", "temporary-directory-package-install"},
            ),
            (
                "custom-install",
                "example-deps",
                "post_install() {\n    cd /tmp\n    npm install atomic-lockfile\n}\n",
                ("install=example-deps",),
                {"install-script", "scriptlet-package-manager", "temporary-directory-package-install"},
            ),
        )
        for name, filename, content, pkgbuild_lines, expected in cases:
            with self.subTest(name=name):
                def fetcher(_update: AurUpdate, target: Path) -> None:
                    write_metadata(
                        target,
                        "example-bin",
                        "1.1",
                        "1",
                        checksum=None,
                        extra_lines=pkgbuild_lines,
                    )
                    (target / filename).write_text(content, encoding="utf-8")

                result = review_updates(
                    [AurUpdate("example-bin", "1.0-1", "1.1-1")],
                    AurCache(self.root / name, fetcher=fetcher),
                )
                self.assertTrue(expected <= {finding.rule_id for finding in result.findings})

    def test_missing_baseline_is_reconstructed_from_installed_version_commit(self) -> None:
        cases = (
            ("normal", None, "1.0-1", "1.1-1"),
            ("epoch", "2", "2:1.0-1", "2:1.1-1"),
        )
        for name, epoch, old_version, new_version in cases:
            with self.subTest(name=name):
                root, repo = self.root / name, self.root / name / "repo"
                repo.mkdir(parents=True)
                for command in (
                    ("init",),
                    ("config", "user.email", "test@example.invalid"),
                    ("config", "user.name", "Test User"),
                ):
                    run_git(repo, *command)
                write_metadata(repo, "example-bin", "1.0", "1", epoch=epoch)
                run_git(repo, "add", "PKGBUILD")
                run_git(repo, "commit", "-m", "old")
                write_metadata(repo, "example-bin", "1.1", "1", epoch=epoch)
                run_git(repo, "commit", "-am", "new")
                update = AurUpdate("example-bin", old_version, new_version)
                cache = AurCache(root / "cache", fetcher=copy_repo_fetcher(repo))
                result = review_updates([update], cache)
                self.assertEqual(cache.baseline_version(update.package), old_version)
                self.assertIn("pkgver=1.0", (cache.baseline_dir(update.package) / "PKGBUILD").read_text(encoding="utf-8"))
                self.assertIn("Initialized review baseline", " ".join(result.reviews[0].notes))

    def test_epoch_refresh_requires_the_complete_installed_version(self) -> None:
        for name, installed, refreshed in (("exact", "2:1.1-1", True), ("missing-epoch", "1.1-1", False)):
            with self.subTest(name=name):
                root = self.root / name
                update = AurUpdate("example-bin", "2:1.0-1", "2:1.1-1")

                def fetcher(_update: AurUpdate, target: Path) -> None:
                    write_metadata(target, "example-bin", "1.1", "1", epoch="2")

                cache = AurCache(root, fetcher=fetcher)
                write_metadata(cache.baseline_dir(update.package), update.package, "1.0", "1", epoch="2")
                (cache.baseline_dir(update.package) / ".aur-sentinel-baseline-version").write_text("2:1.0-1", encoding="utf-8")
                result = refresh_reviewed_baselines(
                    [update],
                    cache,
                    installed_version_getter=lambda package: installed,
                )
                self.assertEqual(result.reviews[0].baseline_refreshed, refreshed)
                self.assertEqual(cache.baseline_version(update.package), "2:1.1-1" if refreshed else "2:1.0-1")

    def test_pending_refresh_states(self) -> None:
        cases = (
            ("not-installed", "abc", False, "1.0-1", False, False, "1.0-1"),
            ("installed", "abc", False, "1.1-1", True, False, "1.1-1"),
            ("findings-blocked", "SKIP", False, "1.1-1", False, True, "1.0-1"),
            ("forced-findings", "SKIP", True, "1.1-1", True, False, "1.1-1"),
            ("forced-mismatch", "SKIP", True, "1.0-1", False, False, "1.0-1"),
        )
        for name, checksum, force, installed, refreshed, blocked, baseline_version in cases:
            with self.subTest(name=name):
                update, cache = reviewed_cache(self.root / name, checksum=checksum)
                result = refresh_reviewed_baselines(
                    [update],
                    cache,
                    force=force,
                    installed_version_getter=lambda package: installed,
                )
                self.assertEqual(result.reviews[0].baseline_refreshed, refreshed)
                self.assertEqual(result.refresh_blocked, blocked)
                self.assertEqual(cache.baseline_version(update.package), baseline_version)
                if name == "not-installed":
                    self.assertIn("Review baseline was not refreshed.", result.reviews[0].notes)

    def test_force_refresh_never_bypasses_incomplete_analysis(self) -> None:
        update = AurUpdate("example-bin", "1.0-1", "1.1-1")

        def fetcher(_update: AurUpdate, target: Path) -> None:
            write_metadata(target, "example-bin", "1.1", "1")
            (target / "example.install").write_bytes(b"\xff")

        cache = AurCache(self.root, fetcher=fetcher)
        write_metadata(cache.baseline_dir(update.package), update.package, "1.0", "1")
        result = refresh_reviewed_baselines(
            [update],
            cache,
            force=True,
            installed_version_getter=lambda package: "1.1-1",
        )
        self.assertTrue(result.analysis_incomplete)
        self.assertTrue(result.refresh_blocked)
        self.assertFalse(result.reviews[0].baseline_refreshed)
        self.assertEqual(cache.baseline_version(update.package), "1.0-1")

    def test_refresh_baseline_handles_partial_update_from_cache(self) -> None:
        cache = AurCache(self.root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('abc')"))
        write_cached_pair(cache, "pkg-a", ("1.0", "1"), ("1.1", "1"))
        write_cached_pair(cache, "pkg-b", ("2.0", "1"), ("2.1", "1"))
        result = refresh_reviewed_baselines(
            [AurUpdate("pkg-a", "1.0-1", "1.1-1")],
            cache,
            installed_version_getter=lambda package: {"pkg-a": "1.0-1", "pkg-b": "2.1-1"}[package],
        )
        refreshed = {review.update.package for review in result.reviews if review.baseline_refreshed}
        self.assertEqual(refreshed, {"pkg-b"})
        self.assertEqual(cache.baseline_version("pkg-a"), "1.0-1")
        self.assertEqual(cache.baseline_version("pkg-b"), "2.1-1")

    def test_refresh_baseline_prefers_fresh_pending_metadata_over_stale_cache(self) -> None:
        update, cache = reviewed_cache(self.root, new_pkgver="1.2")
        write_metadata(cache.latest_dir(update.package), update.package, "1.1", "1")
        result = refresh_reviewed_baselines(
            [update],
            cache,
            installed_version_getter=lambda package: "1.2-1",
        )
        self.assertTrue(result.reviews[0].baseline_refreshed)
        self.assertEqual(result.reviews[0].update.new_version, "1.2-1")
        self.assertEqual(cache.baseline_version(update.package), "1.2-1")
        self.assertIn("pkgver=1.2", (cache.baseline_dir(update.package) / "PKGBUILD").read_text(encoding="utf-8"))

    def test_cached_refresh_states(self) -> None:
        cases = (
            ("matching", ("1.0", "1"), ("1.1", "1"), "1.1-1", True, "1.1-1", None),
            ("mismatch", ("1.0", "1"), ("1.1", "1"), "1.0-1", False, "1.0-1", "not refreshed"),
            ("unknown", ("1.0", "1"), ("1.1", "1"), None, False, "1.0-1", "could not be determined"),
            ("already", ("1.1", "1"), ("1.1", "1"), "1.1-1", False, "1.1-1", "already matches"),
        )
        for name, baseline, latest, installed, refreshed, expected_version, note in cases:
            with self.subTest(name=name):
                cache = AurCache(self.root / name)
                write_cached_pair(cache, "example-bin", baseline, latest)
                result = refresh_reviewed_baselines(
                    [],
                    cache,
                    installed_version_getter=lambda package: installed,
                )
                self.assertTrue(result.cache_refresh)
                self.assertEqual(result.reviews[0].baseline_refreshed, refreshed)
                self.assertEqual(cache.baseline_version("example-bin"), expected_version)
                if note:
                    self.assertIn(note, " ".join(result.reviews[0].notes).lower())

    def test_cached_refresh_ignores_latest_without_baseline(self) -> None:
        cache = AurCache(self.root)
        write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")
        result = refresh_reviewed_baselines(
            [],
            cache,
            installed_version_getter=lambda package: "1.1-1",
        )
        self.assertEqual(result.reviews, [])
