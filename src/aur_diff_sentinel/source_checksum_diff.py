from __future__ import annotations

from urllib.parse import urlparse

from aur_diff_sentinel.diff_findings import array_finding, value_finding
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.pkgbuild_diff_parser import (
    DiffArrays,
    DiffValue,
    checksum_arrays_by_suffix,
    is_checksum,
    is_checksum_array,
    is_source_url,
    is_vcs_source,
    old_checksum_value,
    source_arrays_by_suffix,
    source_for_checksum_value,
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
    removed: list[DiffValue],
    added: list[DiffValue],
) -> list[Finding]:
    old_urls = [value for value in removed if is_source_url(value)]
    new_urls = [value for value in added if is_source_url(value)]
    findings: list[Finding] = []

    for index, new_url in enumerate(new_urls):
        old_url = old_urls[index] if index < len(old_urls) else None
        if old_url is None:
            findings.append(
                value_finding(
                    rule_id="source-url-added",
                    severity=Severity.MEDIUM,
                    message="Source URL added",
                    hint="New source URLs should be reviewed before updating.",
                    value=new_url,
                    old_value=None,
                    new_value=new_url.value,
                )
            )
            continue

        old_parsed = urlparse(old_url.value)
        new_parsed = urlparse(new_url.value)
        old_domain = old_parsed.netloc.lower()
        new_domain = new_parsed.netloc.lower()

        if old_parsed.scheme.lower() == "https" and new_parsed.scheme.lower() == "http":
            findings.append(
                value_finding(
                    rule_id="https-to-http-downgrade",
                    severity=Severity.HIGH,
                    message="Source URL changed from HTTPS to HTTP",
                    hint="A transport security downgrade should be reviewed carefully.",
                    value=new_url,
                    old_value=old_url.value,
                    new_value=new_url.value,
                )
            )

        if old_domain and new_domain and old_domain != new_domain:
            findings.append(
                value_finding(
                    rule_id="source-domain-changed",
                    severity=Severity.HIGH,
                    message=f"Source domain changed from {old_domain} to {new_domain}",
                    hint="A changed source host can indicate a meaningful upstream or supply-chain change.",
                    value=new_url,
                    old_value=old_url.value,
                    new_value=new_url.value,
                )
            )

    return findings


def find_removed_checksum_arrays(arrays: DiffArrays) -> list[Finding]:
    findings: list[Finding] = []
    new_checksums_by_suffix = checksum_arrays_by_suffix(arrays.new_state)

    for old_array in arrays.removed:
        if not is_checksum_array(old_array):
            continue
        if old_array.suffix in new_checksums_by_suffix:
            continue
        findings.append(
            array_finding(
                rule_id="checksum-array-removed",
                severity=Severity.HIGH,
                message="Checksum array was removed",
                hint="Removing checksums weakens source verification and should be reviewed.",
                array=old_array,
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
            array_finding(
                rule_id="checksum-algorithm-weakened",
                severity=Severity.HIGH,
                message=f"Checksum algorithm changed from {old_array.name} to {new_array.name}",
                hint="Changing to a weaker checksum algorithm reduces review confidence.",
                array=new_array,
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
        if checksum_array is None:
            continue
        if not source_array.values or not checksum_array.values:
            continue
        if len(source_array.values) == len(checksum_array.values):
            continue

        findings.append(
            array_finding(
                rule_id="checksum-count-mismatch",
                severity=Severity.MEDIUM,
                message="Source and checksum counts differ",
                hint="Each source entry should normally have a matching checksum entry.",
                array=checksum_array,
                old_value=str(len(source_array.values)),
                new_value=str(len(checksum_array.values)),
            )
        )

    return findings


def find_added_checksum_skips(arrays: DiffArrays) -> list[Finding]:
    old_checksums_by_suffix = checksum_arrays_by_suffix(arrays.old_state)
    new_sources_by_suffix = source_arrays_by_suffix(arrays.new_state)
    findings: list[Finding] = []

    for new_value in (value for value in arrays.added_values if is_checksum(value)):
        old_value = old_checksum_value(new_value, old_checksums_by_suffix)
        if new_value.value == "SKIP" and old_value != "SKIP":
            source_value = source_for_checksum_value(new_value, new_sources_by_suffix)
            severity = Severity.MEDIUM if is_vcs_source(source_value) else Severity.HIGH
            findings.append(
                value_finding(
                    rule_id="checksum-skip-added",
                    severity=severity,
                    message="Checksum SKIP added",
                    hint=checksum_skip_hint(severity),
                    value=new_value,
                    old_value=old_value,
                    new_value=new_value.value,
                )
            )

    return findings


def checksum_skip_hint(severity: Severity) -> str:
    if severity == Severity.MEDIUM:
        return "SKIP is common for VCS sources, but the source should still be reviewed."
    return "A newly skipped checksum weakens source verification."
