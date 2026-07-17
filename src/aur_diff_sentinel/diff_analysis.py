from __future__ import annotations

from collections.abc import Callable

from aur_diff_sentinel.dependency_diff import (
    dedupe_srcinfo_dependency_findings,
    find_dependency_changes,
    find_srcinfo_dependency_changes,
)
from aur_diff_sentinel.metadata_diff import find_added_metadata_files
from aur_diff_sentinel.models import Finding
from aur_diff_sentinel.pkgbuild_diff_parser import collect_diff_arrays
from aur_diff_sentinel.source_checksum_diff import (
    compare_source_urls,
    find_added_checksum_skips,
    find_checksum_algorithm_weakening,
    find_checksum_count_mismatches,
    find_removed_checksum_arrays,
)


def analyze_source_diff(
    text: str,
    *,
    is_aur_package: Callable[[str], bool] | None = None,
) -> list[Finding]:
    arrays = collect_diff_arrays(text)
    findings: list[Finding] = find_added_metadata_files(text)

    for scoped_arrays in arrays.by_filename():
        findings.extend(compare_source_urls(scoped_arrays.removed_values, scoped_arrays.added_values))
        findings.extend(find_removed_checksum_arrays(scoped_arrays))
        findings.extend(find_checksum_algorithm_weakening(scoped_arrays))
        findings.extend(find_checksum_count_mismatches(scoped_arrays))
        findings.extend(find_added_checksum_skips(scoped_arrays))
        findings.extend(find_dependency_changes(scoped_arrays, is_aur_package=is_aur_package))
    findings.extend(
        dedupe_srcinfo_dependency_findings(
            findings,
            find_srcinfo_dependency_changes(text, is_aur_package=is_aur_package),
        )
    )

    return findings
