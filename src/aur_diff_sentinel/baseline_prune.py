from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.provider import InstalledPackageStatus, query_installed_package


InstallStatusGetter = Callable[[str], InstalledPackageStatus]


@dataclass
class BaselinePruneScan:
    candidates: list[str] = field(default_factory=list)
    unknown: list[InstalledPackageStatus] = field(default_factory=list)


@dataclass
class BaselinePruneResult:
    pruned: list[str] = field(default_factory=list)
    unknown: list[InstalledPackageStatus] = field(default_factory=list)


class SelectionError(ValueError):
    pass


def scan_prune_candidates(
    cache: AurCache,
    *,
    install_status_getter: InstallStatusGetter | None = None,
) -> BaselinePruneScan:
    install_status_getter = install_status_getter or query_installed_package
    scan = BaselinePruneScan()

    for package in cache.reviewed_cached_packages():
        status = install_status_getter(package)
        if status.version is not None:
            continue
        if status.missing:
            scan.candidates.append(package)
            continue
        scan.unknown.append(status)

    return scan


def prune_cached_packages(cache: AurCache, packages: Sequence[str]) -> BaselinePruneResult:
    result = BaselinePruneResult()
    for package in packages:
        cache.prune_package(package)
        result.pruned.append(package)
    return result


def parse_prune_selection(selection: str, candidate_count: int) -> list[int]:
    value = selection.strip().lower()
    if not value or value == "none":
        return []
    if value == "all":
        return list(range(candidate_count))

    selected: list[int] = []
    seen: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            raise SelectionError("empty selection item")
        indexes = _parse_selection_part(part, candidate_count)
        for index in indexes:
            if index not in seen:
                selected.append(index)
                seen.add(index)
    return selected


def _parse_selection_part(part: str, candidate_count: int) -> list[int]:
    if "-" in part:
        bounds = part.split("-", maxsplit=1)
        if len(bounds) != 2 or not bounds[0] or not bounds[1]:
            raise SelectionError(f"invalid range: {part}")
        start = _parse_selection_number(bounds[0], candidate_count)
        end = _parse_selection_number(bounds[1], candidate_count)
        if end < start:
            raise SelectionError(f"invalid range: {part}")
        return list(range(start, end + 1))

    return [_parse_selection_number(part, candidate_count)]


def _parse_selection_number(value: str, candidate_count: int) -> int:
    if not value.isdigit():
        raise SelectionError(f"invalid selection: {value}")
    number = int(value)
    if number < 1 or number > candidate_count:
        raise SelectionError(f"selection out of range: {value}")
    return number - 1
