from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
COMMAND_TIMEOUT_SECONDS = 60
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9@._+-]+$")


@dataclass(frozen=True)
class AurUpdate:
    package: str
    old_version: str
    new_version: str


@dataclass(frozen=True)
class InstalledPackageStatus:
    package: str
    version: str | None = None
    missing: bool = False
    error: str | None = None


def default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run an argument vector without a shell and with a fixed timeout."""
    try:
        return subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{command[0]} timed out after {COMMAND_TIMEOUT_SECONDS} seconds") from exc
    except OSError as exc:
        raise RuntimeError(f"cannot run {command[0]}: {exc}") from exc


def detect_helper() -> str | None:
    for helper in ("paru", "yay"):
        if shutil.which(helper):
            return helper
    return None


def discover_updates(
    helper: str | None = None,
    *,
    runner: CommandRunner = default_runner,
) -> list[AurUpdate]:
    selected_helper = helper or detect_helper()
    if selected_helper is None:
        raise RuntimeError("no supported AUR helper found; install paru or yay, or pass --helper")
    if selected_helper not in {"paru", "yay"}:
        raise RuntimeError(f"unsupported AUR helper: {selected_helper}")

    result = runner([selected_helper, "-Qua"])
    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "unknown helper error"
        if not result.stdout.strip() and not result.stderr.strip():
            return []
        raise RuntimeError(f"{selected_helper} -Qua failed: {error}")

    return parse_update_output(result.stdout)


def installed_version(
    package: str,
    *,
    runner: CommandRunner = default_runner,
) -> str | None:
    status = query_installed_package(package, runner=runner)
    return status.version


def query_installed_package(
    package: str,
    *,
    runner: CommandRunner = default_runner,
) -> InstalledPackageStatus:
    validate_package_name(package)
    try:
        result = runner(["pacman", "-Q", package])
    except (OSError, RuntimeError) as exc:
        return InstalledPackageStatus(package=package, error=str(exc))
    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "unknown pacman error"
        return InstalledPackageStatus(
            package=package,
            missing=_is_not_installed_error(error),
            error=error,
        )

    parts = result.stdout.split()
    if len(parts) >= 2 and parts[0] == package:
        return InstalledPackageStatus(package=package, version=parts[1])
    return InstalledPackageStatus(
        package=package,
        error="pacman returned unexpected package query output",
    )


def _is_not_installed_error(error: str) -> bool:
    lowered = error.lower()
    return "package '" in lowered and "was not found" in lowered


def validate_package_name(package: str) -> None:
    if (
        not package
        or package[0] in ".-"
        or not PACKAGE_NAME_RE.fullmatch(package)
    ):
        raise RuntimeError(f"invalid AUR package name: {package!r}")


_AUR_NAME_PATTERN = re.compile(
    r"-(?:git|bin|svn|hg|bzr|nightly|insider|alpha|beta|rc\d*|dev|patched|appindicator)$"
)


def looks_like_aur_package_name(package: str) -> bool:
    return _AUR_NAME_PATTERN.search(package) is not None


def is_aur_package(
    package: str,
    *,
    runner: CommandRunner = default_runner,
) -> bool:
    if looks_like_aur_package_name(package):
        return True
    try:
        validate_package_name(package)
        result = runner(["pacman", "-Si", package])
    except (RuntimeError, OSError):
        return False
    if result.returncode == 0:
        return False
    error = result.stderr.strip() or result.stdout.strip()
    return _is_not_installed_error(error)


def parse_update_output(output: str) -> list[AurUpdate]:
    updates: list[AurUpdate] = []

    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue

        if "->" in parts:
            arrow_index = parts.index("->")
            if arrow_index < 2 or arrow_index + 1 >= len(parts):
                continue
            old_version, new_version = parts[arrow_index - 1], parts[arrow_index + 1]
        elif len(parts) >= 3:
            old_version, new_version = parts[1:3]
        else:
            continue
        validate_package_name(parts[0])
        updates.append(AurUpdate(parts[0], old_version, new_version))

    return updates
