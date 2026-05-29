from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlparse

from aur_diff_sentinel.models import Finding, Severity


ARRAY_START_RE = re.compile(
    r"^\s*(source(?:_[a-z0-9_]+)?|(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[a-z0-9_]+)?)\s*=\s*(.*)$",
    re.IGNORECASE,
)
SOURCE_ARRAY_RE = re.compile(r"^source(?P<suffix>_[a-z0-9_]+)?$", re.IGNORECASE)
CHECKSUM_ARRAY_RE = re.compile(
    r"^(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?P<suffix>_[a-z0-9_]+)?$",
    re.IGNORECASE,
)
VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


@dataclass(frozen=True)
class PkgbuildArrayValue:
    name: str
    value: str
    index: int
    line_number: int
    line_content: str

    @property
    def suffix(self) -> str:
        source_match = SOURCE_ARRAY_RE.match(self.name)
        if source_match:
            return source_match.group("suffix") or ""

        checksum_match = CHECKSUM_ARRAY_RE.match(self.name)
        if checksum_match:
            return checksum_match.group("suffix") or ""

        return ""


@dataclass
class ArrayBlock:
    name: str
    values: list[PkgbuildArrayValue]


def analyze_pkgbuild_checksums(text: str, *, filename: str | None = None) -> list[Finding]:
    values = _collect_array_values(text)
    sources_by_suffix = _sources_by_suffix(values)
    findings: list[Finding] = []

    for checksum in (value for value in values if _is_checksum(value)):
        if checksum.value != "SKIP":
            continue

        source = _source_for_checksum(checksum, sources_by_suffix)
        severity = Severity.MEDIUM if _is_vcs_source(source) else Severity.HIGH
        findings.append(
            Finding(
                rule_id="checksum-skip",
                severity=severity,
                message="Checksum verification skipped",
                line_number=checksum.line_number,
                line_content=checksum.line_content,
                hint=_checksum_skip_hint(severity),
                filename=filename,
            )
        )

    return findings


def _collect_array_values(text: str) -> list[PkgbuildArrayValue]:
    values: list[PkgbuildArrayValue] = []
    active_block: ArrayBlock | None = None

    for line_number, line in enumerate(text.splitlines(), start=1):
        if active_block is not None:
            segment, closed = _array_segment(line)
            _append_values(active_block, segment, line_number, line)
            if closed:
                values.extend(active_block.values)
                active_block = None
            continue

        match = ARRAY_START_RE.match(line)
        if not match:
            continue

        rest = match.group(2)
        if "(" not in rest:
            continue

        name = match.group(1)
        segment, closed = _array_segment(rest[rest.find("(") + 1 :])
        block = ArrayBlock(name=name, values=[])
        _append_values(block, segment, line_number, line)
        if closed:
            values.extend(block.values)
        else:
            active_block = block

    return values


def _array_segment(text: str) -> tuple[str, bool]:
    if ")" not in text:
        return text, False
    return text[: text.find(")")], True


def _append_values(
    block: ArrayBlock,
    segment: str,
    line_number: int,
    line_content: str,
) -> None:
    for value in _split_values(segment):
        block.values.append(
            PkgbuildArrayValue(
                name=block.name,
                value=value,
                index=len(block.values),
                line_number=line_number,
                line_content=line_content,
            )
        )


def _split_values(segment: str) -> list[str]:
    try:
        return shlex.split(segment, comments=True, posix=True)
    except ValueError:
        return []


def _sources_by_suffix(
    values: list[PkgbuildArrayValue],
) -> dict[str, list[PkgbuildArrayValue]]:
    sources: dict[str, list[PkgbuildArrayValue]] = {}
    for value in values:
        if SOURCE_ARRAY_RE.match(value.name):
            sources.setdefault(value.suffix, []).append(value)
    return sources


def _source_for_checksum(
    checksum: PkgbuildArrayValue,
    sources_by_suffix: dict[str, list[PkgbuildArrayValue]],
) -> str | None:
    sources = sources_by_suffix.get(checksum.suffix)
    if sources is None or checksum.index >= len(sources):
        return None
    return sources[checksum.index].value


def _is_checksum(value: PkgbuildArrayValue) -> bool:
    return CHECKSUM_ARRAY_RE.match(value.name) is not None


def _is_vcs_source(source: str | None) -> bool:
    if source is None:
        return False
    lowered = _source_without_alias(source).lower()
    return lowered.startswith(VCS_PREFIXES) or urlparse(lowered).path.endswith(".git")


def _source_without_alias(source: str) -> str:
    if "::" not in source:
        return source
    return source.split("::", 1)[1]


def _checksum_skip_hint(severity: Severity) -> str:
    if severity == Severity.MEDIUM:
        return "SKIP is common for VCS sources, but the source should still be reviewed."
    return "SKIP skips source verification and should be reviewed carefully."
