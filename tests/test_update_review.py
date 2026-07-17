from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aur_diff_sentinel.cache import AurCache, metadata_version, unified_diff_dirs
from aur_diff_sentinel.provider import AurUpdate
from aur_diff_sentinel.report import format_update_review
from aur_diff_sentinel.scanner import scan_diff_text
from aur_diff_sentinel.update_review import (
    refresh_reviewed_baselines,
    review_updates,
)
from tests.helpers import (
    copy_repo_fetcher,
    fixture_fetcher,
    run_git,
    write_metadata,
)

class UpdateWorkflowTests(unittest.TestCase):
    def test_metadata_version_reads_srcinfo_and_pkgbuild_shapes(self) -> None:
        self.assertEqual(metadata_version("pkgver = 1.0\npkgrel = 2\n"), "1.0-2")
        self.assertEqual(metadata_version("pkgver=1.0\npkgrel=2\n"), "1.0-2")
        self.assertEqual(metadata_version("epoch = 2\npkgver = 1.0\npkgrel = 2\n"), "2:1.0-2")
        self.assertEqual(metadata_version("epoch='2'\npkgver=1.0\npkgrel=2\n"), "2:1.0-2")
        self.assertEqual(metadata_version("epoch=0\npkgver=1.0\npkgrel=2\n"), "1.0-2")
        self.assertIsNone(metadata_version("epoch=$epoch\npkgver=1.0\npkgrel=2\n"))

    def test_fetch_latest_rejects_invalid_package_before_fetcher_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            called = False

            def fetcher(_update: AurUpdate, _target: Path) -> None:
                nonlocal called
                called = True

            cache = AurCache(Path(temp_dir), fetcher=fetcher)

            with self.assertRaisesRegex(RuntimeError, "invalid AUR package name"):
                cache.fetch_latest(AurUpdate("../evil", "1.0-1", "1.1-1"))

            self.assertFalse(called)
            self.assertFalse((Path(temp_dir) / "latest").exists())

    def test_refresh_baseline_rejects_invalid_package_before_replacing_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            write_metadata(root / "baselines" / "example-bin", "example-bin", "1.0", "1")
            write_metadata(root / "latest" / "example-bin", "example-bin", "1.1", "1")

            with self.assertRaisesRegex(RuntimeError, "invalid AUR package name"):
                cache.refresh_baseline(
                    AurUpdate("../example-bin", "1.0-1", "1.1-1"),
                    root / "latest" / "example-bin",
                )

            self.assertEqual(cache.baseline_version("example-bin"), "1.0-1")

    def test_reviewed_cached_packages_ignores_invalid_cache_directory_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root)
            write_metadata(root / "baselines" / "example-bin", "example-bin", "1.0", "1")
            write_metadata(root / "latest" / "example-bin", "example-bin", "1.1", "1")
            write_metadata(root / "baselines" / ".hidden", ".hidden", "1.0", "1")
            write_metadata(root / "latest" / ".hidden", ".hidden", "1.1", "1")

            self.assertEqual(cache.reviewed_cached_packages(), ["example-bin"])

    def test_cache_path_guard_refuses_symlink_escape_before_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "cache"
            outside = Path(temp_dir) / "outside"
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

            result = review_updates([update], cache)

            self.assertTrue(result.has_findings)
            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_cache_diff_uses_dev_null_for_added_metadata_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old_dir = root / "old"
            new_dir = root / "new"
            old_dir.mkdir()
            new_dir.mkdir()
            (new_dir / "example.install").write_text(
                "post_install() {\n    echo done\n}\n",
                encoding="utf-8",
            )

            diff_text = unified_diff_dirs(old_dir, new_dir)

            self.assertIn("--- /dev/null", diff_text)
            self.assertIn("+++ b/example.install", diff_text)
            self.assertIn("install-script-added", {finding.rule_id for finding in scan_diff_text(diff_text)})

    def test_cache_diff_added_hook_file_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old_dir = root / "old"
            new_dir = root / "new"
            old_dir.mkdir()
            new_dir.mkdir()
            (new_dir / "example.hook").write_text(
                "[Action]\nExec = /bin/sh -c 'npm install package'\n",
                encoding="utf-8",
            )

            ids = {finding.rule_id for finding in scan_diff_text(unified_diff_dirs(old_dir, new_dir))}

            self.assertIn("pacman-hook-added", ids)
            self.assertIn("scriptlet-package-manager", ids)

    def test_cache_diff_added_shell_script_file_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old_dir = root / "old"
            new_dir = root / "new"
            old_dir.mkdir()
            new_dir.mkdir()
            (new_dir / "helper").write_text("#!/bin/sh\necho done\n", encoding="utf-8")

            ids = {finding.rule_id for finding in scan_diff_text(unified_diff_dirs(old_dir, new_dir))}

            self.assertIn("aur-metadata-executable-added", ids)

    def test_updates_detects_added_elf_metadata_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root)
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\n",
                encoding="utf-8",
            )
            (baseline / ".aur-sentinel-baseline-version").write_text("1.0-1", encoding="utf-8")

            def fetcher(_update: AurUpdate, target: Path) -> None:
                target.mkdir(parents=True)
                (target / "PKGBUILD").write_text(
                    "pkgname=example-bin\npkgver=1.1\npkgrel=1\n",
                    encoding="utf-8",
                )
                (target / "payload").write_bytes(b"\x7fELF\xff\x00")

            cache.fetcher = fetcher

            result = review_updates([update], cache)

            self.assertIn("aur-metadata-elf-added", {finding.rule_id for finding in result.findings})

    def test_updates_review_path_reports_bun_install_sequence_and_keeps_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root)
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "\n".join(
                    [
                        "pkgname=example-bin",
                        "pkgver=1.0",
                        "pkgrel=1",
                        "depends=(pencil)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (baseline / ".aur-sentinel-baseline-version").write_text("1.0-1", encoding="utf-8")

            def fetcher(_update: AurUpdate, target: Path) -> None:
                target.mkdir(parents=True)
                (target / "PKGBUILD").write_text(
                    "\n".join(
                        [
                            "pkgname=example-bin",
                            "pkgver=1.1",
                            "pkgrel=1",
                            "depends=(pencil bun)",
                            "install=example-deps.install",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )
                (target / ".SRCINFO").write_text(
                    "\n".join(
                        [
                            "pkgbase = example-bin",
                            "\tdepends = pencil",
                            "\tdepends = bun",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )
                (target / "example-deps.install").write_text(
                    "\n".join(
                        [
                            "post_install() {",
                            "    cd /tmp",
                            "    bun add lodash js-digest",
                            "}",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )

            cache.fetcher = fetcher

            result = review_updates([update], cache)
            ids = {finding.rule_id for finding in result.findings}
            report = format_update_review(result)

            self.assertIn("install-script", ids)
            self.assertIn("install-script-added", ids)
            self.assertIn("javascript-tooling-dependency-added", ids)
            self.assertIn("scriptlet-package-manager", ids)
            self.assertIn("temporary-directory-package-install", ids)
            self.assertIn("suspicious-live-install-sequence", ids)
            self.assertIn("High attention:", report)
            self.assertIn("example-bin", report)
            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_missing_baseline_scans_latest_without_initializing_to_latest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(
                Path(temp_dir),
                fetcher=fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"),
            )

            result = review_updates([update], cache)

            self.assertTrue(result.has_findings)
            self.assertFalse(cache.has_baseline(update.package))
            self.assertIn("no update diff was reviewed", " ".join(result.reviews[0].notes).lower())

    def test_missing_baseline_scans_hook_files_in_latest_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")

            def fetcher(_update: AurUpdate, target: Path) -> None:
                target.mkdir(parents=True)
                (target / "PKGBUILD").write_text(
                    "pkgname=example-bin\npkgver=1.1\npkgrel=1\n",
                    encoding="utf-8",
                )
                (target / "example.hook").write_text(
                    "\n".join(
                        [
                            "[Action]",
                            "Exec = /bin/sh -c 'cd /tmp && npm install atomic-lockfile'",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )

            cache = AurCache(Path(temp_dir), fetcher=fetcher)

            result = review_updates([update], cache)
            ids = {finding.rule_id for finding in result.findings}

            self.assertIn("pacman-hook-exec", ids)
            self.assertIn("scriptlet-package-manager", ids)
            self.assertIn("temporary-directory-package-install", ids)

    def test_missing_baseline_scans_install_referenced_custom_script(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")

            def fetcher(_update: AurUpdate, target: Path) -> None:
                target.mkdir(parents=True)
                (target / "PKGBUILD").write_text(
                    "\n".join(
                        [
                            "pkgname=example-bin",
                            "pkgver=1.1",
                            "pkgrel=1",
                            "install=example-deps",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )
                (target / "example-deps").write_text(
                    "\n".join(
                        [
                            "post_install() {",
                            "    cd /tmp",
                            "    npm install atomic-lockfile",
                            "}",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )

            cache = AurCache(Path(temp_dir), fetcher=fetcher)

            result = review_updates([update], cache)
            ids = {finding.rule_id for finding in result.findings}

            self.assertIn("install-script", ids)
            self.assertIn("scriptlet-package-manager", ids)
            self.assertIn("temporary-directory-package-install", ids)

    def test_missing_baseline_is_reconstructed_from_installed_version_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            run_git(repo, "init")
            run_git(repo, "config", "user.email", "test@example.invalid")
            run_git(repo, "config", "user.name", "Test User")
            (repo / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            run_git(repo, "add", "PKGBUILD")
            run_git(repo, "commit", "-m", "old")
            (repo / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.1\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            run_git(repo, "commit", "-am", "new")

            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root / "cache", fetcher=copy_repo_fetcher(repo))

            result = review_updates([update], cache)

            self.assertTrue(cache.has_baseline(update.package))
            self.assertIn(
                "pkgver=1.0",
                (cache.baseline_dir(update.package) / "PKGBUILD").read_text(encoding="utf-8"),
            )
            self.assertIn("Initialized review baseline", " ".join(result.reviews[0].notes))

    def test_epoch_package_reconstructs_installed_baseline_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            run_git(repo, "init")
            run_git(repo, "config", "user.email", "test@example.invalid")
            run_git(repo, "config", "user.name", "Test User")
            (repo / "PKGBUILD").write_text(
                "pkgname=example-bin\nepoch=2\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            run_git(repo, "add", "PKGBUILD")
            run_git(repo, "commit", "-m", "old")
            (repo / "PKGBUILD").write_text(
                "pkgname=example-bin\nepoch=2\npkgver=1.1\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            run_git(repo, "commit", "-am", "new")

            update = AurUpdate("example-bin", "2:1.0-1", "2:1.1-1")
            cache = AurCache(root / "cache", fetcher=copy_repo_fetcher(repo))

            result = review_updates([update], cache)

            self.assertEqual(cache.baseline_version(update.package), "2:1.0-1")
            self.assertIn(
                "pkgver=1.0",
                (cache.baseline_dir(update.package) / "PKGBUILD").read_text(encoding="utf-8"),
            )
            self.assertIn("Initialized review baseline", " ".join(result.reviews[0].notes))

    def test_epoch_refresh_requires_the_complete_installed_version(self) -> None:
        for name, installed, refreshed in (
            ("exact", "2:1.1-1", True),
            ("missing-epoch", "1.1-1", False),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                update = AurUpdate("example-bin", "2:1.0-1", "2:1.1-1")

                def fetcher(_update: AurUpdate, target: Path) -> None:
                    target.mkdir(parents=True)
                    (target / "PKGBUILD").write_text(
                        "pkgname=example-bin\nepoch=2\npkgver=1.1\npkgrel=1\nsha256sums=('abc')\n",
                        encoding="utf-8",
                    )

                cache = AurCache(root, fetcher=fetcher)
                baseline = cache.baseline_dir(update.package)
                baseline.mkdir(parents=True)
                (baseline / "PKGBUILD").write_text(
                    "pkgname=example-bin\nepoch=2\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                    encoding="utf-8",
                )
                (baseline / ".aur-sentinel-baseline-version").write_text(
                    "2:1.0-1",
                    encoding="utf-8",
                )

                result = refresh_reviewed_baselines(
                    [update],
                    cache,
                    installed_version_getter=lambda package: installed,
                )

                self.assertEqual(result.reviews[0].baseline_refreshed, refreshed)
                self.assertEqual(
                    cache.baseline_version(update.package),
                    "2:1.1-1" if refreshed else "2:1.0-1",
                )

    def test_refresh_baseline_skips_pending_update_not_installed_yet(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('abc')"))
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            (baseline / ".aur-sentinel-baseline-version").write_text("1.0-1", encoding="utf-8")

            result = refresh_reviewed_baselines(
                [update],
                cache,
                installed_version_getter=lambda package: "1.0-1",
            )

            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertEqual(cache.baseline_version(update.package), "1.0-1")
            self.assertIn("Review baseline was not refreshed.", result.reviews[0].notes)

    def test_refresh_baseline_updates_pending_update_after_install(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('abc')"))
            baseline = cache.baseline_dir(update.package)
            baseline.mkdir(parents=True)
            (baseline / "PKGBUILD").write_text(
                "pkgname=example-bin\npkgver=1.0\npkgrel=1\nsha256sums=('abc')\n",
                encoding="utf-8",
            )
            (baseline / ".aur-sentinel-baseline-version").write_text("1.0-1", encoding="utf-8")

            result = refresh_reviewed_baselines(
                [update],
                cache,
                installed_version_getter=lambda package: "1.1-1",
            )

            self.assertTrue(result.reviews[0].baseline_refreshed)
            self.assertEqual(cache.baseline_version(update.package), "1.1-1")

    def test_refresh_baseline_is_blocked_when_installed_update_has_findings(self) -> None:
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

            result = refresh_reviewed_baselines(
                [update],
                cache,
                installed_version_getter=lambda package: "1.1-1",
            )

            self.assertTrue(result.refresh_blocked)
            self.assertIn("pkgver=1.0", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_force_refresh_updates_installed_baseline_even_with_findings(self) -> None:
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

            result = refresh_reviewed_baselines(
                [update],
                cache,
                force=True,
                installed_version_getter=lambda package: "1.1-1",
            )

            self.assertFalse(result.refresh_blocked)
            self.assertTrue(result.reviews[0].baseline_refreshed)
            self.assertIn("pkgver=1.1", (baseline / "PKGBUILD").read_text(encoding="utf-8"))

    def test_force_refresh_does_not_bypass_installed_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.1-1")
            cache = AurCache(root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('SKIP')"))
            write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")

            result = refresh_reviewed_baselines(
                [update],
                cache,
                force=True,
                installed_version_getter=lambda package: "1.0-1",
            )

            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertEqual(cache.baseline_version("example-bin"), "1.0-1")

    def test_refresh_baseline_handles_partial_update_from_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = AurCache(root, fetcher=fixture_fetcher("1.1", "1", "sha256sums=('abc')"))
            write_metadata(cache.baseline_dir("pkg-a"), "pkg-a", "1.0", "1")
            write_metadata(cache.latest_dir("pkg-a"), "pkg-a", "1.1", "1")
            write_metadata(cache.baseline_dir("pkg-b"), "pkg-b", "2.0", "1")
            write_metadata(cache.latest_dir("pkg-b"), "pkg-b", "2.1", "1")

            result = refresh_reviewed_baselines(
                [AurUpdate("pkg-a", "1.0-1", "1.1-1")],
                cache,
                installed_version_getter=lambda package: {
                    "pkg-a": "1.0-1",
                    "pkg-b": "2.1-1",
                }[package],
            )

            refreshed = {
                review.update.package
                for review in result.reviews
                if review.baseline_refreshed
            }
            self.assertEqual(refreshed, {"pkg-b"})
            self.assertEqual(cache.baseline_version("pkg-a"), "1.0-1")
            self.assertEqual(cache.baseline_version("pkg-b"), "2.1-1")

    def test_refresh_baseline_prefers_fresh_pending_metadata_over_stale_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            update = AurUpdate("example-bin", "1.0-1", "1.2-1")
            cache = AurCache(root, fetcher=fixture_fetcher("1.2", "1", "sha256sums=('abc')"))
            write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_reviewed_baselines(
                [update],
                cache,
                installed_version_getter=lambda package: "1.2-1",
            )

            self.assertTrue(result.reviews[0].baseline_refreshed)
            self.assertEqual(result.reviews[0].update.new_version, "1.2-1")
            self.assertEqual(cache.baseline_version("example-bin"), "1.2-1")
            self.assertIn(
                "pkgver=1.2",
                (cache.baseline_dir("example-bin") / "PKGBUILD").read_text(encoding="utf-8"),
            )

    def test_cached_refresh_updates_baseline_when_installed_matches_latest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_reviewed_baselines(
                [], cache,
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
            write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_reviewed_baselines(
                [], cache,
                installed_version_getter=lambda package: "1.0-1",
            )

            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertEqual(cache.baseline_version("example-bin"), "1.0-1")
            self.assertIn("Review baseline was not refreshed.", result.reviews[0].notes)

    def test_cached_refresh_skips_when_installed_version_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.0", "1")
            write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_reviewed_baselines(
                [],
                cache,
                installed_version_getter=lambda package: None,
            )

            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertEqual(cache.baseline_version("example-bin"), "1.0-1")
            self.assertIn(
                "Installed package version could not be determined.",
                result.reviews[0].notes,
            )

    def test_cached_refresh_ignores_latest_without_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_reviewed_baselines(
                [], cache,
                installed_version_getter=lambda package: "1.1-1",
            )

            self.assertEqual(result.reviews, [])

    def test_cached_refresh_skips_when_baseline_already_matches_latest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AurCache(Path(temp_dir))
            write_metadata(cache.baseline_dir("example-bin"), "example-bin", "1.1", "1")
            write_metadata(cache.latest_dir("example-bin"), "example-bin", "1.1", "1")

            result = refresh_reviewed_baselines(
                [], cache,
                installed_version_getter=lambda package: "1.1-1",
            )

            self.assertFalse(result.reviews[0].baseline_refreshed)
            self.assertIn("already matches", result.reviews[0].notes[0])
