from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.diff_analysis import analyze_metadata_tree_changes
from aur_diff_sentinel.models import Finding
from aur_diff_sentinel.provider import AurUpdate, installed_version
from aur_diff_sentinel.scanner import scan_diff_text, scan_text


InstalledVersionGetter = Callable[[str], str | None]
MAX_METADATA_SCAN_BYTES = 512 * 1024
INSTALL_FIELD_RE = re.compile(r"^\s*install\s*=\s*['\"]?([^'\"\s#]+)", re.MULTILINE)


@dataclass(frozen=True)
class RefreshCandidate:
    update: AurUpdate
    latest_dir: Path


@dataclass
class PackageReview:
    update: AurUpdate
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    baseline_available: bool = False
    baseline_refreshed: bool = False
    refresh_blocked: bool = False


@dataclass
class UpdateReviewResult:
    reviews: list[PackageReview]
    refresh_requested: bool = False
    force_refresh: bool = False
    cache_refresh: bool = False
    pending_update_count: int = 0

    @property
    def findings(self) -> list[Finding]:
        return [
            finding
            for review in self.reviews
            for finding in review.findings
        ]

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def refresh_blocked(self) -> bool:
        return any(review.refresh_blocked for review in self.reviews)


def review_updates(
    updates: list[AurUpdate],
    cache: AurCache,
) -> UpdateReviewResult:
    reviews: list[PackageReview] = []

    for update in updates:
        latest_dir = cache.fetch_latest(update)
        review = PackageReview(update=update)

        if not cache.has_baseline(update.package):
            if cache.initialize_baseline_from_installed_version(update, latest_dir):
                review.baseline_available = True
                review.notes.append(
                    f"Initialized review baseline for installed version {update.old_version}."
                )
            else:
                review.notes.append(
                    f"No review baseline could be found for installed version {update.old_version}."
                )
                review.notes.append(
                    "Current AUR metadata was scanned, but no update diff was reviewed."
                )

        else:
            review.baseline_available = True

        if review.baseline_available:
            review.findings = _review_metadata_changes(cache, update.package, latest_dir)
        else:
            review.findings = _scan_latest_metadata(latest_dir)

        reviews.append(review)

    return UpdateReviewResult(reviews=reviews)


def refresh_cached_reviewed_baselines(
    cache: AurCache,
    *,
    installed_version_getter: InstalledVersionGetter | None = None,
) -> UpdateReviewResult:
    return refresh_reviewed_baselines(
        [],
        cache,
        installed_version_getter=installed_version_getter,
    )


def refresh_reviewed_baselines(
    updates: list[AurUpdate],
    cache: AurCache,
    *,
    force: bool = False,
    installed_version_getter: InstalledVersionGetter | None = None,
) -> UpdateReviewResult:
    installed_version_getter = installed_version_getter or installed_version
    candidates = _refresh_candidates(updates, cache)
    reviews = [
        _refresh_candidate(
            candidate,
            cache,
            force=force,
            installed_version_getter=installed_version_getter,
        )
        for candidate in candidates
    ]

    return UpdateReviewResult(
        reviews=reviews,
        refresh_requested=True,
        force_refresh=force,
        cache_refresh=True,
        pending_update_count=len(updates),
    )


def _refresh_candidates(
    updates: list[AurUpdate],
    cache: AurCache,
) -> list[RefreshCandidate]:
    candidates: dict[str, RefreshCandidate] = {}

    for update in updates:
        latest_dir = cache.fetch_latest(update)
        latest_version = cache.latest_version(update.package) or update.new_version
        candidates[update.package] = RefreshCandidate(
            update=AurUpdate(update.package, update.old_version, latest_version),
            latest_dir=latest_dir,
        )

    for package in cache.reviewed_cached_packages():
        if package in candidates:
            continue
        baseline_version = cache.baseline_version(package)
        latest_version = cache.latest_version(package)
        if baseline_version is None or latest_version is None:
            continue
        candidates[package] = RefreshCandidate(
            update=AurUpdate(package, baseline_version, latest_version),
            latest_dir=cache.latest_dir(package),
        )

    return list(candidates.values())


def _refresh_candidate(
    candidate: RefreshCandidate,
    cache: AurCache,
    *,
    force: bool,
    installed_version_getter: InstalledVersionGetter,
) -> PackageReview:
    update = candidate.update
    review = PackageReview(
        update=update,
        baseline_available=cache.has_baseline(update.package),
    )

    if not review.baseline_available:
        review.notes.append("No review baseline exists for this package.")
        review.notes.append("Review baseline was not refreshed.")
        return review

    if update.old_version == update.new_version:
        review.notes.append("Review baseline already matches reviewed metadata.")
        return review

    current_installed_version = installed_version_getter(update.package)
    if current_installed_version != update.new_version:
        if current_installed_version is None:
            review.notes.append("Installed package version could not be determined.")
        else:
            review.notes.append(
                f"Installed version is {current_installed_version}, "
                f"but reviewed metadata is {update.new_version}."
            )
        review.notes.append("Review baseline was not refreshed.")
        return review

    review.findings = _review_metadata_changes(cache, update.package, candidate.latest_dir)
    if review.findings and not force:
        review.refresh_blocked = True
        review.notes.append("Review baseline was not refreshed.")
        return review

    cache.refresh_baseline(update, candidate.latest_dir)
    review.baseline_refreshed = True
    review.notes.append(
        f"Refreshed review baseline for installed version {update.new_version}."
    )
    return review


def _review_metadata_changes(cache: AurCache, package: str, latest_dir: Path) -> list[Finding]:
    diff_text = cache.diff_baseline_to_latest(package, latest_dir)
    install_references = _install_references(latest_dir)
    return _dedupe_findings(
        [
            *(scan_diff_text(diff_text, scriptlet_files=install_references) if diff_text else []),
            *analyze_metadata_tree_changes(cache.baseline_dir(package), latest_dir),
        ]
    )


def _scan_latest_metadata(latest_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    install_references = _install_references(latest_dir)
    for path in _metadata_scan_paths(latest_dir):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(
            scan_text(
                text,
                filename=path.relative_to(latest_dir).as_posix(),
                scriptlet_files=install_references,
            )
        )
    findings.extend(analyze_metadata_tree_changes(latest_dir / ".aur-sentinel-empty-baseline", latest_dir))
    return _dedupe_findings(findings)


def _metadata_scan_paths(latest_dir: Path) -> list[Path]:
    if not latest_dir.exists():
        return []
    install_references = _install_references(latest_dir)
    paths: list[Path] = []
    for path in latest_dir.rglob("*"):
        if not _is_scannable_metadata_path(latest_dir, path):
            continue
        relative_path = path.relative_to(latest_dir)
        if (
            path.name in {"PKGBUILD", ".SRCINFO"}
            or path.name.endswith(".install")
            or path.name.endswith(".hook")
            or relative_path.as_posix() in install_references
            or path.name in install_references
        ):
            paths.append(path)
    return paths


def _install_references(latest_dir: Path) -> set[str]:
    pkgbuild = latest_dir / "PKGBUILD"
    if not pkgbuild.exists() or pkgbuild.is_symlink():
        return set()
    try:
        text = pkgbuild.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return set()
    return {match.group(1) for match in INSTALL_FIELD_RE.finditer(text)}


def _is_scannable_metadata_path(root: Path, path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    relative_path = path.relative_to(root)
    if ".git" in relative_path.parts:
        return False
    try:
        return path.stat().st_size <= MAX_METADATA_SCAN_BYTES
    except OSError:
        return False


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str | None, int, str | None, str | None]] = set()
    for finding in findings:
        key = (
            finding.rule_id,
            finding.filename,
            finding.line_number,
            finding.old_value,
            finding.new_value,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
