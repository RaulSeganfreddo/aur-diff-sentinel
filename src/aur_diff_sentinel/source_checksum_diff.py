from __future__ import annotations

from urllib.parse import urlparse

from aur_diff_sentinel.diff_findings import diff_finding
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.pkgbuild_analysis import checksum_skip_hint
from aur_diff_sentinel.pkgbuild_diff_parser import (
    DiffArrays,
    checksum_arrays_by_suffix,
    paired_array_value,
    source_arrays_by_suffix,
)
from aur_diff_sentinel.pkgbuild_syntax import (
    ArrayValue,
    array_suffix,
    is_checksum_name,
    is_source_name,
    is_vcs_source,
    source_without_alias,
)


CHECKSUM_STRENGTH = {
    "md5": 1,
    "sha1": 2,
    "sha224": 3,
    "sha256": 4,
    "sha384": 5,
    "sha512": 6,
    "b2": 7,
}


def compare_source_urls(
    removed: list[ArrayValue],
    added: list[ArrayValue],
) -> list[Finding]:
    findings: list[Finding] = []
    old_groups = _source_url_groups(removed)
    new_groups = _source_url_groups(added)

    for key, new_urls in new_groups.items():
        old_urls = list(old_groups.get(key, ()))
        unmatched_new: list[ArrayValue] = []
        for new_url in new_urls:
            canonical = source_without_alias(new_url.value)
            match = next(
                (
                    index
                    for index, old_url in enumerate(old_urls)
                    if source_without_alias(old_url.value) == canonical
                ),
                None,
            )
            if match is None:
                unmatched_new.append(new_url)
            else:
                old_urls.pop(match)

        paired_count = min(len(old_urls), len(unmatched_new))
        for old_url, new_url in zip(old_urls[:paired_count], unmatched_new[:paired_count]):
            _append_url_change_findings(findings, old_url, new_url)
        for new_url in unmatched_new[paired_count:]:
            findings.append(
                diff_finding(
                    rule_id="source-url-added",
                    severity=Severity.MEDIUM,
                    message="Source URL added",
                    hint="New source URLs should be reviewed before updating.",
                    location=new_url,
                    old_value=None,
                    new_value=new_url.value,
                )
            )

    return findings


def _source_url_groups(values: list[ArrayValue]) -> dict[tuple[str | None, str], list[ArrayValue]]:
    groups: dict[tuple[str | None, str], list[ArrayValue]] = {}
    for value in values:
        if is_source_name(value.name) and urlparse(source_without_alias(value.value)).scheme in {"http", "https"}:
            groups.setdefault((value.filename, array_suffix(value.name)), []).append(value)
    return groups


def _append_url_change_findings(
    findings: list[Finding],
    old_url: ArrayValue,
    new_url: ArrayValue,
) -> None:
    old_parsed = urlparse(source_without_alias(old_url.value))
    new_parsed = urlparse(source_without_alias(new_url.value))
    old_domain = old_parsed.netloc.lower()
    new_domain = new_parsed.netloc.lower()
    if old_parsed.scheme.lower() == "https" and new_parsed.scheme.lower() == "http":
        findings.append(
            diff_finding(
                rule_id="https-to-http-downgrade",
                severity=Severity.HIGH,
                message="Source URL changed from HTTPS to HTTP",
                hint="A transport security downgrade should be reviewed carefully.",
                location=new_url,
                old_value=old_url.value,
                new_value=new_url.value,
            )
        )
    if old_domain and new_domain and old_domain != new_domain:
        findings.append(
            diff_finding(
                rule_id="source-domain-changed",
                severity=Severity.HIGH,
                message=f"Source domain changed from {old_domain} to {new_domain}",
                hint="A changed source host can indicate a meaningful upstream or supply-chain change.",
                location=new_url,
                old_value=old_url.value,
                new_value=new_url.value,
            )
        )


def find_removed_checksum_arrays(arrays: DiffArrays) -> list[Finding]:
    findings: list[Finding] = []
    new_checksums_by_suffix = checksum_arrays_by_suffix(arrays.new_state)

    for old_array in arrays.removed:
        if is_checksum_name(old_array.name) and old_array.suffix.lower() not in new_checksums_by_suffix:
            findings.append(
                diff_finding(
                    rule_id="checksum-array-removed",
                    severity=Severity.HIGH,
                    message="Checksum array was removed",
                    hint="Removing checksums weakens source verification and should be reviewed.",
                    location=old_array,
                    old_value=old_array.name,
                    new_value=None,
                )
            )

    return findings


def find_checksum_algorithm_weakening(arrays: DiffArrays) -> list[Finding]:
    findings: list[Finding] = []
    old_checksums = checksum_arrays_by_suffix(arrays.old_state)
    changed_new_checksums = checksum_arrays_by_suffix(arrays.added)

    for suffix, new_array in changed_new_checksums.items():
        old_array = old_checksums.get(suffix)
        if old_array is None:
            continue

        old_algorithm = old_array.checksum_algorithm
        new_algorithm = new_array.checksum_algorithm
        if old_algorithm is None or new_algorithm is None:
            continue
        if CHECKSUM_STRENGTH[new_algorithm] >= CHECKSUM_STRENGTH[old_algorithm]:
            continue

        findings.append(
            diff_finding(
                rule_id="checksum-algorithm-weakened",
                severity=Severity.HIGH,
                message=f"Checksum algorithm changed from {old_array.name} to {new_array.name}",
                hint="Changing to a weaker checksum algorithm reduces review confidence.",
                location=new_array,
                old_value=old_array.name,
                new_value=new_array.name,
            )
        )

    return findings


def find_checksum_count_mismatches(arrays: DiffArrays) -> list[Finding]:
    findings: list[Finding] = []
    source_arrays = source_arrays_by_suffix(arrays.new_state)
    checksum_arrays = checksum_arrays_by_suffix(arrays.new_state)

    for suffix, source_array in source_arrays.items():
        checksum_array = checksum_arrays.get(suffix)
        if (
            checksum_array is None
            or not source_array.values
            or not checksum_array.values
            or len(source_array.values) == len(checksum_array.values)
        ):
            continue

        findings.append(
            diff_finding(
                rule_id="checksum-count-mismatch",
                severity=Severity.MEDIUM,
                message="Source and checksum counts differ",
                hint="Each source entry should normally have a matching checksum entry.",
                location=checksum_array,
                old_value=str(len(source_array.values)),
                new_value=str(len(checksum_array.values)),
            )
        )

    return findings


def find_added_checksum_skips(arrays: DiffArrays) -> list[Finding]:
    old_checksums_by_suffix = checksum_arrays_by_suffix(arrays.old_state)
    new_sources_by_suffix = source_arrays_by_suffix(arrays.new_state)
    findings: list[Finding] = []

    for new_value in (value for value in arrays.added_values if is_checksum_name(value.name) and value.value):
        old_value = paired_array_value(new_value, old_checksums_by_suffix)
        if new_value.value == "SKIP" and old_value != "SKIP":
            source_value = paired_array_value(new_value, new_sources_by_suffix)
            severity = Severity.MEDIUM if is_vcs_source(source_value) else Severity.HIGH
            findings.append(
                diff_finding(
                    rule_id="checksum-skip-added",
                    severity=severity,
                    message="Checksum SKIP added",
                    hint=checksum_skip_hint(severity, added=True),
                    location=new_value,
                    old_value=old_value,
                    new_value=new_value.value,
                )
            )

    return findings
