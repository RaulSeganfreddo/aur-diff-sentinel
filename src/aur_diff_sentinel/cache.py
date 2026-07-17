from __future__ import annotations

import difflib
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from aur_diff_sentinel.provider import (
    AurUpdate,
    CommandRunner,
    default_runner,
    validate_package_name,
)


Fetcher = Callable[[AurUpdate, Path], None]

BASELINE_VERSION_FILE = ".aur-sentinel-baseline-version"
VERSION_FIELD_RE = re.compile(r"^(epoch|pkgver|pkgrel)\s*=\s*(.*?)\s*$")


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
        return self._package_dir("baselines", package)

    def latest_dir(self, package: str) -> Path:
        return self._package_dir("latest", package)

    def reviewed_cached_packages(self) -> list[str]:
        baseline_root = self.root / "baselines"
        latest_root = self.root / "latest"
        if not baseline_root.exists() or not latest_root.exists():
            return []
        return sorted(
            path.name
            for path in latest_root.iterdir()
            if path.is_dir()
            and is_valid_package_name(path.name)
            and (baseline_root / path.name).is_dir()
        )

    def fetch_latest(self, update: AurUpdate) -> Path:
        latest_dir = self.latest_dir(update.package)
        _replace_tree(
            latest_dir,
            self.root,
            lambda staging: self.fetcher(update, staging),
        )
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
        def populate(staging: Path) -> None:
            snapshot_commit(latest_dir, commit, staging, runner=self.runner)
            (staging / BASELINE_VERSION_FILE).write_text(update.old_version, encoding="utf-8")

        _replace_tree(baseline_dir, self.root, populate)
        return True

    def refresh_baseline(self, update: AurUpdate, latest_dir: Path) -> None:
        baseline_dir = self.baseline_dir(update.package)
        def populate(staging: Path) -> None:
            copy_metadata_tree(latest_dir, staging)
            (staging / BASELINE_VERSION_FILE).write_text(update.new_version, encoding="utf-8")

        _replace_tree(baseline_dir, self.root, populate)

    def prune_package(self, package: str) -> None:
        for path in (self.baseline_dir(package), self.latest_dir(package)):
            if path.exists():
                shutil.rmtree(path)

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

    def _package_dir(self, namespace: str, package: str) -> Path:
        validate_package_name(package)
        root = self.root / namespace
        path = root / package
        _ensure_path_within(path, self.root)
        return path


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
        if not _is_metadata_path_allowed(Path(relative_path)):
            continue
        file_result = runner(["git", "-C", str(repo_dir), "show", f"{commit}:{relative_path}"])
        if file_result.returncode != 0:
            continue
        destination = target / relative_path
        _ensure_path_within(destination, target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(file_result.stdout, encoding="utf-8")


def metadata_version(text: str) -> str | None:
    epoch: str | None = None
    epoch_present = False
    pkgver: str | None = None
    pkgrel: str | None = None

    for raw_line in text.splitlines():
        match = VERSION_FIELD_RE.match(raw_line.strip())
        if match is None:
            continue
        name, raw_value = match.groups()
        value = _unquote_metadata_value(raw_value)
        if name == "epoch":
            epoch = value
            epoch_present = True
        elif name == "pkgver":
            pkgver = value
        else:
            pkgrel = value

    if not pkgver or not pkgrel:
        return None
    if not epoch_present:
        return f"{pkgver}-{pkgrel}"
    if epoch is None or not epoch.isdecimal():
        return None
    normalized_epoch = int(epoch)
    prefix = f"{normalized_epoch}:" if normalized_epoch else ""
    return f"{prefix}{pkgver}-{pkgrel}"


def _unquote_metadata_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def copy_metadata_tree(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for path in _metadata_paths(source):
        relative_path = path.relative_to(source)
        destination = target / relative_path
        _ensure_path_within(destination, target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)


def unified_diff_dirs(old_dir: Path, new_dir: Path) -> str:
    lines: list[str] = []
    for relative_path in sorted(_relative_metadata_paths(old_dir) | _relative_metadata_paths(new_dir)):
        old_path = old_dir / relative_path
        new_path = new_dir / relative_path
        old_exists = old_path.exists()
        new_exists = new_path.exists()
        old_text = _read_text_or_empty(old_path)
        new_text = _read_text_or_empty(new_path)
        if old_exists == new_exists and old_text == new_text:
            continue

        old_lines = old_text.splitlines(keepends=True)
        new_lines = new_text.splitlines(keepends=True)
        lines.extend(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"a/{relative_path.as_posix()}" if old_exists else "/dev/null",
                tofile=f"b/{relative_path.as_posix()}" if new_exists else "/dev/null",
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
        if path.is_file()
        and not path.is_symlink()
        and _is_metadata_path_allowed(path.relative_to(root))
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


def is_valid_package_name(package: str) -> bool:
    try:
        validate_package_name(package)
    except RuntimeError:
        return False
    return True


def _is_metadata_path_allowed(path: Path) -> bool:
    return (
        bool(path.parts)
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in path.as_posix()
        and not _is_ignored_path(path)
    )


def _ensure_path_within(path: Path, root: Path) -> None:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise RuntimeError(f"refusing to write outside cache directory: {path}")


def _replace_tree(
    target: Path,
    root: Path,
    populate: Callable[[Path], None],
) -> None:
    _ensure_path_within(target, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f".{target.name}-", dir=target.parent))
    staging = work / "new"
    backup = work / "old"
    preserve_backup = False
    try:
        populate(staging)
        if not staging.is_dir():
            raise RuntimeError(f"cache staging tree was not created: {target}")
        if target.exists() or target.is_symlink():
            target.rename(backup)
        try:
            staging.rename(target)
        except OSError as exc:
            if backup.exists() or backup.is_symlink():
                try:
                    backup.rename(target)
                except OSError as rollback_error:
                    preserve_backup = True
                    raise RuntimeError(
                        f"failed to replace cache tree and rollback; backup preserved at {backup}: "
                        f"{rollback_error}"
                    ) from exc
            raise
    except OSError as exc:
        raise RuntimeError(f"failed to replace cache tree {target}: {exc}") from exc
    finally:
        if not preserve_backup:
            shutil.rmtree(work, ignore_errors=True)
