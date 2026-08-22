from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from aur_diff_sentinel.cache import AurCache, CacheMutationError, read_metadata_text
from aur_diff_sentinel.metadata_diff import analyze_metadata_tree_changes
from aur_diff_sentinel.models import Finding
from aur_diff_sentinel.provider import AurUpdate, is_aur_package, installed_version
from aur_diff_sentinel.scanner import scan_diff_text, scan_text


InstalledVersionGetter = Callable[[str], str | None]
AurPackageChecker = Callable[[str], bool]
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
    analysis_errors: list[str] = field(default_factory=list)
    baseline_refreshed: bool = False
    refresh_blocked: bool = False


@dataclass
class UpdateReviewResult:
    reviews: list[PackageReview]
    cache_refresh: bool = False
    pending_update_count: int = 0

    @property
    def findings(self) -> list[Finding]:
        return [finding for review in self.reviews for finding in review.findings]

    @property
    def has_findings(self) -> bool:
        return any(review.findings for review in self.reviews)

    @property
    def refresh_blocked(self) -> bool:
        return any(review.refresh_blocked for review in self.reviews)

    @property
    def analysis_incomplete(self) -> bool:
        return any(review.analysis_errors for review in self.reviews)


def review_updates(
    updates: list[AurUpdate],
    cache: AurCache,
    *,
    aur_package_checker: AurPackageChecker = is_aur_package,
) -> UpdateReviewResult:
    """Review updates without installing packages or advancing existing baselines."""
    aur_package_checker = functools.lru_cache(maxsize=None)(aur_package_checker)
    reviews: list[PackageReview] = []

    for update in updates:
        latest_dir, failed_review = _fetch_candidate_metadata(update, cache)
        if failed_review is not None:
            reviews.append(failed_review)
            continue
        assert latest_dir is not None
        review = PackageReview(update=update)
        baseline_available = cache.has_baseline(update.package)

        if not baseline_available:
            if cache.initialize_baseline_from_installed_version(update, latest_dir):
                baseline_available = True
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
        if baseline_available:
            review.findings, review.analysis_errors = _review_metadata_changes(
                cache, update.package, latest_dir, aur_package_checker
            )
        else:
            review.findings, review.analysis_errors = _scan_latest_metadata(latest_dir)

        reviews.append(review)

    return UpdateReviewResult(reviews=reviews)


def refresh_reviewed_baselines(
    updates: list[AurUpdate],
    cache: AurCache,
    *,
    force: bool = False,
    installed_version_getter: InstalledVersionGetter | None = None,
    aur_package_checker: AurPackageChecker = is_aur_package,
) -> UpdateReviewResult:
    """Refresh only complete reviewed metadata matching installed versions."""
    installed_version_getter = installed_version_getter or installed_version
    aur_package_checker = functools.lru_cache(maxsize=None)(aur_package_checker)
    reviews: list[PackageReview] = []
    for candidate in _refresh_candidates(updates, cache):
        if isinstance(candidate, PackageReview):
            reviews.append(candidate)
            continue
        reviews.append(
            _refresh_candidate(
                candidate,
                cache,
                force=force,
                installed_version_getter=installed_version_getter,
                aur_package_checker=aur_package_checker,
            )
        )

    return UpdateReviewResult(
        reviews=reviews,
        cache_refresh=True,
        pending_update_count=len(updates),
    )


def _refresh_candidates(
    updates: list[AurUpdate],
    cache: AurCache,
) -> list[RefreshCandidate | PackageReview]:
    candidates: list[RefreshCandidate | PackageReview] = []
    pending_packages: set[str] = set()

    for update in updates:
        pending_packages.add(update.package)
        latest_dir, failed_review = _fetch_candidate_metadata(update, cache)
        if failed_review is not None:
            failed_review.refresh_blocked = True
            failed_review.notes.append("Review baseline was not refreshed.")
            candidates.append(failed_review)
            continue
        assert latest_dir is not None
        latest_version = cache.latest_version(update.package) or update.new_version
        candidates.append(
            RefreshCandidate(
                update=AurUpdate(update.package, update.old_version, latest_version),
                latest_dir=latest_dir,
            )
        )

    for package in cache.reviewed_cached_packages():
        if package in pending_packages:
            continue
        baseline_version = cache.baseline_version(package)
        latest_version = cache.latest_version(package)
        if baseline_version is None or latest_version is None:
            continue
        candidates.append(
            RefreshCandidate(
                update=AurUpdate(package, baseline_version, latest_version),
                latest_dir=cache.latest_dir(package),
            )
        )

    return candidates


def _fetch_candidate_metadata(
    update: AurUpdate,
    cache: AurCache,
) -> tuple[Path | None, PackageReview | None]:
    try:
        return cache.fetch_latest(update), None
    except CacheMutationError:
        raise
    except RuntimeError as exc:
        return None, PackageReview(
            update=update,
            notes=["Candidate metadata was not analyzed."],
            analysis_errors=[f"candidate metadata fetch failed: {exc}"],
        )


def _refresh_candidate(
    candidate: RefreshCandidate,
    cache: AurCache,
    *,
    force: bool,
    installed_version_getter: InstalledVersionGetter,
    aur_package_checker: AurPackageChecker,
) -> PackageReview:
    update = candidate.update
    review = PackageReview(update=update)

    if not cache.has_baseline(update.package):
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

    review.findings, review.analysis_errors = _review_metadata_changes(
        cache, update.package, candidate.latest_dir, aur_package_checker
    )
    if review.analysis_errors:
        review.refresh_blocked = True
        review.notes.append("Review baseline was not refreshed because analysis was incomplete.")
        return review
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


def _review_metadata_changes(
    cache: AurCache,
    package: str,
    latest_dir: Path,
    aur_package_checker: AurPackageChecker,
) -> tuple[list[Finding], list[str]]:
    diff_text, errors = cache.diff_baseline_to_latest(package, latest_dir)
    findings = (
        scan_diff_text(
            diff_text,
            scriptlet_files=_install_references(latest_dir),
            is_aur_package=aur_package_checker,
        )
        if diff_text
        else []
    )
    findings.extend(analyze_metadata_tree_changes(cache.baseline_dir(package), latest_dir))
    return _dedupe_findings(findings), list(dict.fromkeys(errors))


def _scan_latest_metadata(latest_dir: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    install_references = _install_references(latest_dir)
    for path in _metadata_scan_paths(latest_dir):
        relative = path.relative_to(latest_dir)
        text, error = read_metadata_text(path, relative, "candidate")
        if error:
            errors.append(error)
            continue
        findings.extend(
            scan_text(
                text,
                filename=relative.as_posix(),
                scriptlet_files=install_references,
            )
    )
    findings.extend(analyze_metadata_tree_changes(latest_dir / ".aur-sentinel-empty-baseline", latest_dir))
    return _dedupe_findings(findings), list(dict.fromkeys(errors))


def _metadata_scan_paths(latest_dir: Path) -> list[Path]:
    if not latest_dir.exists():
        return []
    install_references = _install_references(latest_dir)
    paths: list[Path] = []
    for path in latest_dir.rglob("*"):
        relative_path = path.relative_to(latest_dir)
        if ".git" in relative_path.parts or not (path.is_file() or path.is_symlink()):
            continue
        if (
            path.name in {"PKGBUILD", ".SRCINFO"}
            or path.name.endswith(".install")
            or path.name.endswith(".hook")
            or relative_path.as_posix() in install_references
            or path.name in install_references
        ):
            paths.append(path)
    return sorted(paths)


def _install_references(latest_dir: Path) -> set[str]:
    pkgbuild = latest_dir / "PKGBUILD"
    text, error = read_metadata_text(pkgbuild, Path("PKGBUILD"), "candidate")
    return set() if error else {match.group(1) for match in INSTALL_FIELD_RE.finditer(text)}


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[tuple[str, str | None, int, str | None, str | None], Finding] = {}
    for finding in findings:
        key = (
            finding.rule_id,
            finding.filename,
            finding.line_number,
            finding.old_value,
            finding.new_value,
        )
        deduped.setdefault(key, finding)
    return list(deduped.values())
