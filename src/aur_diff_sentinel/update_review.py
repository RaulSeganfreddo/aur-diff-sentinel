from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.models import Finding
from aur_diff_sentinel.provider import AurUpdate
from aur_diff_sentinel.scanner import scan_diff_text, scan_text


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
    *,
    refresh_baseline: bool = False,
    force: bool = False,
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
            diff_text = cache.diff_baseline_to_latest(update.package, latest_dir)
            review.findings = scan_diff_text(diff_text) if diff_text else []
        else:
            review.findings = _scan_latest_metadata(latest_dir)

        if refresh_baseline:
            if review.findings and not force:
                review.refresh_blocked = True
            else:
                cache.refresh_baseline(update, latest_dir)
                review.baseline_refreshed = True

        reviews.append(review)

    return UpdateReviewResult(
        reviews=reviews,
        refresh_requested=refresh_baseline,
        force_refresh=force,
    )


def _scan_latest_metadata(latest_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _metadata_scan_paths(latest_dir):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text(text, filename=path.name))
    return findings


def _metadata_scan_paths(latest_dir: Path) -> list[Path]:
    if not latest_dir.exists():
        return []
    return [
        path
        for path in latest_dir.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(latest_dir).parts
        and (path.name == "PKGBUILD" or path.name.endswith(".install"))
    ]
