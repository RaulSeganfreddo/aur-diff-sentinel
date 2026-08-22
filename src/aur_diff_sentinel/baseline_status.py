from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.provider import InstalledPackageStatus, query_installed_package


InstallStatusGetter = Callable[[str], InstalledPackageStatus]


class BaselineState(StrEnum):
    CURRENT = "current"
    READY = "ready"
    PENDING = "pending"
    UNREVIEWED = "unreviewed"
    NOT_INSTALLED = "not-installed"
    UNKNOWN = "unknown"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class BaselineStatusItem:
    package: str
    state: BaselineState
    baseline_version: str | None = None
    reviewed_version: str | None = None
    installed_version: str | None = None
    note: str | None = None


def scan_baseline_status(
    cache: AurCache,
    *,
    install_status_getter: InstallStatusGetter | None = None,
) -> list[BaselineStatusItem]:
    get_status = install_status_getter or query_installed_package
    items: list[BaselineStatusItem] = []

    for package in cache.reviewed_cached_packages():
        baseline = cache.baseline_version(package)
        reviewed = cache.latest_version(package)
        if baseline is None:
            items.append(
                BaselineStatusItem(
                    package,
                    BaselineState.INCOMPLETE,
                    reviewed_version=reviewed,
                    note="baseline version could not be determined",
                )
            )
            continue

        status = get_status(package)
        if status.version is None:
            state = BaselineState.NOT_INSTALLED if status.missing else BaselineState.UNKNOWN
            items.append(
                BaselineStatusItem(
                    package,
                    state,
                    baseline,
                    reviewed or baseline,
                    note=status.error,
                )
            )
            continue

        if reviewed is None:
            state = BaselineState.CURRENT if status.version == baseline else BaselineState.INCOMPLETE
            note = None if state is BaselineState.CURRENT else "reviewed metadata version could not be determined"
            items.append(
                BaselineStatusItem(
                    package,
                    state,
                    baseline,
                    baseline if state is BaselineState.CURRENT else None,
                    status.version,
                    note,
                )
            )
            continue

        if status.version == baseline == reviewed:
            state = BaselineState.CURRENT
        elif status.version == reviewed:
            state = BaselineState.READY
        elif status.version == baseline:
            state = BaselineState.PENDING
        else:
            state = BaselineState.UNREVIEWED
        items.append(BaselineStatusItem(package, state, baseline, reviewed, status.version))

    return items


GROUPS = (
    (BaselineState.CURRENT, "Current:", ()),
    (
        BaselineState.READY,
        "Ready to refresh:",
        (
            "To refresh matching installed baselines, run: aur-diff-sentinel baseline refresh",
            "If reviewed findings are intentionally accepted, use: aur-diff-sentinel baseline refresh --force",
        ),
    ),
    (BaselineState.PENDING, "Pending reviewed metadata:", ()),
    (BaselineState.UNREVIEWED, "Installed not reviewed:", ()),
    (
        BaselineState.NOT_INSTALLED,
        "Not installed:",
        ("To remove sentinel cache for packages no longer installed, run: aur-diff-sentinel baseline prune",),
    ),
    (BaselineState.UNKNOWN, "Unknown:", ()),
    (BaselineState.INCOMPLETE, "Incomplete cache:", ()),
)


def format_baseline_status(items: list[BaselineStatusItem]) -> str:
    lines = [f"Cached baselines: {len(items)}", ""]
    if not items:
        return "\n".join((*lines, "No cached baselines found.", "No packages were updated."))

    for state, title, hints in GROUPS:
        group = [item for item in items if item.state is state]
        if not group:
            continue
        lines.append(title)
        lines.extend(_format_item(item) for item in group)
        if hints:
            lines.append("")
            lines.extend(hints)
        lines.append("")

    lines.extend(("No packages were updated.",))
    return "\n".join(lines)


def _format_item(item: BaselineStatusItem) -> str:
    if item.state is BaselineState.CURRENT:
        return f"- {item.package}: installed {item.installed_version}, baseline {item.baseline_version}"
    if item.state is BaselineState.NOT_INSTALLED:
        return f"- {item.package}: baseline {item.baseline_version}, reviewed {item.reviewed_version}"
    if item.state in {BaselineState.UNKNOWN, BaselineState.INCOMPLETE}:
        fallback = (
            "installed package status could not be determined"
            if item.state is BaselineState.UNKNOWN
            else "cache metadata could not be interpreted"
        )
        return f"- {item.package}: {item.note or fallback}"
    return (
        f"- {item.package}: installed {item.installed_version}, "
        f"baseline {item.baseline_version}, reviewed {item.reviewed_version}"
    )
