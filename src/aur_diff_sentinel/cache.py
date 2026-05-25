from __future__ import annotations

import difflib
import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from aur_diff_sentinel.provider import AurUpdate, CommandRunner, default_runner


Fetcher = Callable[[AurUpdate, Path], None]

BASELINE_VERSION_FILE = ".aur-sentinel-baseline-version"


def default_cache_root() -> Path:
    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        return Path(xdg_cache_home) / "aur-diff-sentinel"
    return Path.home() / ".cache" / "aur-diff-sentinel"


class AurCache:
    def __init__(
        self,
        root: Path | None = None,
        *,
        runner: CommandRunner = default_runner,
        fetcher: Fetcher | None = None,
    ) -> None:
        self.root = root or default_cache_root()
        self.runner = runner
        self.fetcher = fetcher or self._default_fetcher

    def baseline_dir(self, package: str) -> Path:
        return self.root / "baselines" / package

    def latest_dir(self, package: str) -> Path:
        return self.root / "latest" / package

    def reviewed_cached_packages(self) -> list[str]:
        baseline_root = self.root / "baselines"
        latest_root = self.root / "latest"
        if not baseline_root.exists() or not latest_root.exists():
            return []
        return sorted(
            path.name
            for path in latest_root.iterdir()
            if path.is_dir() and (baseline_root / path.name).is_dir()
        )

    def fetch_latest(self, update: AurUpdate) -> Path:
        latest_dir = self.latest_dir(update.package)
        if latest_dir.exists():
            shutil.rmtree(latest_dir)
        latest_dir.parent.mkdir(parents=True, exist_ok=True)
        self.fetcher(update, latest_dir)
        return latest_dir

    def has_baseline(self, package: str) -> bool:
        return self.baseline_dir(package).exists()

    def baseline_version(self, package: str) -> str | None:
        version_file = self.baseline_dir(package) / BASELINE_VERSION_FILE
        if not version_file.exists():
            return None
        try:
            version = version_file.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return version or None

    def latest_version(self, package: str) -> str | None:
        latest_dir = self.latest_dir(package)
        for path_name in (".SRCINFO", "PKGBUILD"):
            path = latest_dir / path_name
            if not path.exists():
                continue
            try:
                version = metadata_version(path.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                continue
            if version:
                return version
        return None

    def initialize_baseline_from_installed_version(
        self,
        update: AurUpdate,
        latest_dir: Path,
    ) -> bool:
        commit = find_commit_for_version(latest_dir, update.old_version, runner=self.runner)
        if commit is None:
            return False

        baseline_dir = self.baseline_dir(update.package)
        if baseline_dir.exists():
            shutil.rmtree(baseline_dir)
        baseline_dir.parent.mkdir(parents=True, exist_ok=True)
        snapshot_commit(latest_dir, commit, baseline_dir, runner=self.runner)
        (baseline_dir / BASELINE_VERSION_FILE).write_text(update.old_version, encoding="utf-8")
        return True

    def refresh_baseline(self, update: AurUpdate, latest_dir: Path) -> None:
        baseline_dir = self.baseline_dir(update.package)
        if baseline_dir.exists():
            shutil.rmtree(baseline_dir)
        baseline_dir.parent.mkdir(parents=True, exist_ok=True)
        copy_metadata_tree(latest_dir, baseline_dir)
        (baseline_dir / BASELINE_VERSION_FILE).write_text(update.new_version, encoding="utf-8")

    def diff_baseline_to_latest(self, package: str, latest_dir: Path) -> str:
        return unified_diff_dirs(self.baseline_dir(package), latest_dir)

    def _default_fetcher(self, update: AurUpdate, target: Path) -> None:
        result = self.runner(
            [
                "git",
                "clone",
                "--quiet",
                f"https://aur.archlinux.org/{update.package}.git",
                str(target),
            ]
        )
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or "unknown git error"
            raise RuntimeError(f"failed to fetch {update.package}: {error}")


def find_commit_for_version(
    repo_dir: Path,
    version: str,
    *,
    runner: CommandRunner = default_runner,
) -> str | None:
    result = runner(["git", "-C", str(repo_dir), "rev-list", "HEAD"])
    if result.returncode != 0:
        return None

    for commit in result.stdout.splitlines():
        for path in (".SRCINFO", "PKGBUILD"):
            file_result = runner(["git", "-C", str(repo_dir), "show", f"{commit}:{path}"])
            if file_result.returncode != 0:
                continue
            if metadata_version(file_result.stdout) == version:
                return commit

    return None


def snapshot_commit(
    repo_dir: Path,
    commit: str,
    target: Path,
    *,
    runner: CommandRunner = default_runner,
) -> None:
    paths_result = runner(["git", "-C", str(repo_dir), "ls-tree", "-r", "--name-only", commit])
    if paths_result.returncode != 0:
        error = paths_result.stderr.strip() or paths_result.stdout.strip() or "unknown git error"
        raise RuntimeError(f"failed to list files for baseline commit: {error}")

    target.mkdir(parents=True, exist_ok=True)
    for relative_path in paths_result.stdout.splitlines():
        if not relative_path or _is_ignored_path(Path(relative_path)):
            continue
        file_result = runner(["git", "-C", str(repo_dir), "show", f"{commit}:{relative_path}"])
        if file_result.returncode != 0:
            continue
        destination = target / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(file_result.stdout, encoding="utf-8")


def metadata_version(text: str) -> str | None:
    pkgver: str | None = None
    pkgrel: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("pkgver ="):
            pkgver = line.split("=", maxsplit=1)[1].strip()
        elif line.startswith("pkgrel ="):
            pkgrel = line.split("=", maxsplit=1)[1].strip()
        elif line.startswith("pkgver="):
            pkgver = line.split("=", maxsplit=1)[1].strip().strip("'\"")
        elif line.startswith("pkgrel="):
            pkgrel = line.split("=", maxsplit=1)[1].strip().strip("'\"")

    if pkgver and pkgrel:
        return f"{pkgver}-{pkgrel}"
    return None


def copy_metadata_tree(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for path in _metadata_paths(source):
        relative_path = path.relative_to(source)
        destination = target / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)


def unified_diff_dirs(old_dir: Path, new_dir: Path) -> str:
    lines: list[str] = []
    for relative_path in sorted(_relative_metadata_paths(old_dir) | _relative_metadata_paths(new_dir)):
        old_path = old_dir / relative_path
        new_path = new_dir / relative_path
        old_text = _read_text_or_empty(old_path)
        new_text = _read_text_or_empty(new_path)
        if old_text == new_text:
            continue

        old_lines = old_text.splitlines(keepends=True)
        new_lines = new_text.splitlines(keepends=True)
        lines.extend(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"a/{relative_path.as_posix()}",
                tofile=f"b/{relative_path.as_posix()}",
                lineterm="",
            )
        )

    return "\n".join(line.rstrip("\n") for line in lines)


def _metadata_paths(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return [
        path
        for path in root.rglob("*")
        if path.is_file() and not _is_ignored_path(path.relative_to(root))
    ]


def _relative_metadata_paths(root: Path) -> set[Path]:
    return {path.relative_to(root) for path in _metadata_paths(root)}


def _read_text_or_empty(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def _is_ignored_path(path: Path) -> bool:
    parts = path.parts
    return ".git" in parts or path.name == BASELINE_VERSION_FILE
