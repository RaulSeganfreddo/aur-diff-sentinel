from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.provider import InstalledPackageStatus, query_installed_package


InstallStatusGetter = Callable[[str], InstalledPackageStatus]


@dataclass(frozen=True)
class BaselineStatusItem:
    package: str
    baseline_version: str | None = None
    reviewed_version: str | None = None
    installed_version: str | None = None
    note: str | None = None


@dataclass
class BaselineStatusResult:
    reviewed_count: int
    current: list[BaselineStatusItem] = field(default_factory=list)
    ready_to_refresh: list[BaselineStatusItem] = field(default_factory=list)
    pending: list[BaselineStatusItem] = field(default_factory=list)
    installed_not_reviewed: list[BaselineStatusItem] = field(default_factory=list)
    not_installed: list[BaselineStatusItem] = field(default_factory=list)
    unknown: list[BaselineStatusItem] = field(default_factory=list)
    incomplete: list[BaselineStatusItem] = field(default_factory=list)


def scan_baseline_status(
    cache: AurCache,
    *,
    install_status_getter: InstallStatusGetter | None = None,
) -> BaselineStatusResult:
    install_status_getter = install_status_getter or query_installed_package
    packages = cache.reviewed_cached_packages()
    result = BaselineStatusResult(reviewed_count=len(packages))

    for package in packages:
        baseline_version = cache.baseline_version(package)
        reviewed_version = cache.latest_version(package)
        if baseline_version is None:
            result.incomplete.append(
                BaselineStatusItem(
                    package=package,
                    reviewed_version=reviewed_version,
                    note="baseline version could not be determined",
                )
            )
            continue

        status = install_status_getter(package)
        if status.version is None:
            item = BaselineStatusItem(
                package=package,
                baseline_version=baseline_version,
                reviewed_version=reviewed_version or baseline_version,
                note=status.error,
            )
            if status.missing:
                result.not_installed.append(item)
            else:
                result.unknown.append(item)
            continue

        if reviewed_version is None:
            if status.version == baseline_version:
                result.current.append(
                    BaselineStatusItem(
                        package=package,
                        baseline_version=baseline_version,
                        reviewed_version=baseline_version,
                        installed_version=status.version,
                    )
                )
            else:
                result.incomplete.append(
                    BaselineStatusItem(
                        package=package,
                        baseline_version=baseline_version,
                        installed_version=status.version,
                        note="reviewed metadata version could not be determined",
                    )
                )
            continue

        item = BaselineStatusItem(
            package=package,
            baseline_version=baseline_version,
            reviewed_version=reviewed_version,
            installed_version=status.version,
        )
        if status.version == baseline_version and status.version == reviewed_version:
            result.current.append(item)
        elif status.version == reviewed_version:
            result.ready_to_refresh.append(item)
        elif status.version == baseline_version:
            result.pending.append(item)
        else:
            result.installed_not_reviewed.append(item)

    return result


def format_baseline_status(result: BaselineStatusResult) -> str:
    lines = [f"Cached baselines: {result.reviewed_count}", ""]
    if result.reviewed_count == 0:
        lines.append("No cached baselines found.")
        lines.append("No packages were updated.")
        return "\n".join(lines)

    _extend_group(lines, "Current:", result.current, _format_current_item)
    _extend_group(
        lines,
        "Ready to refresh:",
        result.ready_to_refresh,
        _format_detailed_item,
        hints=(
            "To refresh matching installed baselines, run: "
            "aur-diff-sentinel baseline refresh",
            "If reviewed findings are intentionally accepted, use: "
            "aur-diff-sentinel baseline refresh --force",
        ),
    )
    _extend_group(lines, "Pending reviewed metadata:", result.pending, _format_pending_item)
    _extend_group(lines, "Installed not reviewed:", result.installed_not_reviewed, _format_detailed_item)
    _extend_group(
        lines,
        "Not installed:",
        result.not_installed,
        _format_not_installed_item,
        hints=(
            "To remove sentinel cache for packages no longer installed, run: "
            "aur-diff-sentinel baseline prune",
        ),
    )
    _extend_group(lines, "Unknown:", result.unknown, _format_unknown_item)
    _extend_group(lines, "Incomplete cache:", result.incomplete, _format_incomplete_item)

    if lines[-1] == "":
        lines.pop()
    lines.append("")
    lines.append("No packages were updated.")
    return "\n".join(lines)


def _extend_group(
    lines: list[str],
    title: str,
    items: list[BaselineStatusItem],
    formatter: Callable[[BaselineStatusItem], str],
    *,
    hints: tuple[str, ...] = (),
) -> None:
    if not items:
        return
    lines.append(title)
    lines.extend(formatter(item) for item in items)
    if hints:
        lines.append("")
        lines.extend(hints)
    lines.append("")


def _format_current_item(item: BaselineStatusItem) -> str:
    return (
        f"- {item.package}: installed {item.installed_version}, "
        f"baseline {item.baseline_version}"
    )


def _format_pending_item(item: BaselineStatusItem) -> str:
    return _format_detailed_item(item)


def _format_detailed_item(item: BaselineStatusItem) -> str:
    return (
        f"- {item.package}: installed {item.installed_version}, "
        f"baseline {item.baseline_version}, reviewed {item.reviewed_version}"
    )


def _format_not_installed_item(item: BaselineStatusItem) -> str:
    return (
        f"- {item.package}: baseline {item.baseline_version}, "
        f"reviewed {item.reviewed_version}"
    )


def _format_unknown_item(item: BaselineStatusItem) -> str:
    note = item.note or "installed package status could not be determined"
    return f"- {item.package}: {note}"


def _format_incomplete_item(item: BaselineStatusItem) -> str:
    note = item.note or "cache metadata could not be interpreted"
    return f"- {item.package}: {note}"
