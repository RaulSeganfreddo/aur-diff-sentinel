from __future__ import annotations

from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.pkgbuild_syntax import (
    collect_arrays_from_text,
    is_checksum_name,
    is_source_name,
    is_vcs_source,
    merge_array_assignments,
)


def analyze_pkgbuild_checksums(text: str, *, filename: str | None = None) -> list[Finding]:
    arrays = merge_array_assignments(
        collect_arrays_from_text(text, filename=filename),
        key=lambda array: (array.filename, array.name.lower()),
    ).values()
    sources = {
        (array.filename, array.suffix.lower()): array
        for array in arrays
        if is_source_name(array.name)
    }

    findings: list[Finding] = []
    for array in arrays:
        if not is_checksum_name(array.name):
            continue
        source_array = sources.get((array.filename, array.suffix.lower()))
        for checksum in (value for value in array.values if value.value == "SKIP"):
            source = None
            if source_array is not None and checksum.index < len(source_array.values):
                source = source_array.values[checksum.index].value
            severity = Severity.MEDIUM if is_vcs_source(source) else Severity.HIGH
            findings.append(
                Finding(
                    rule_id="checksum-skip",
                    severity=severity,
                    message="Checksum verification skipped",
                    line_number=checksum.line_number,
                    line_content=checksum.line_content,
                    hint=checksum_skip_hint(severity),
                    filename=filename,
                )
            )
    return findings


def checksum_skip_hint(severity: Severity, *, added: bool = False) -> str:
    if severity == Severity.MEDIUM:
        return "SKIP is common for VCS sources, but the source should still be reviewed."
    if added:
        return "A newly skipped checksum weakens source verification."
    return "SKIP skips source verification and should be reviewed carefully."
