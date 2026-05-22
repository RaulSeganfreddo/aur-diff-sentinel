from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from aur_diff_sentinel.models import Finding, Severity


HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
ARRAY_START_RE = re.compile(
    r"^\s*(source|(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[a-z0-9_]+)?)\s*=\s*(.*)$",
    re.IGNORECASE,
)
SOURCE_ARRAY_RE = re.compile(r"^source(?P<suffix>_[a-z0-9_]+)?$", re.IGNORECASE)
CHECKSUM_ARRAY_RE = re.compile(
    r"^(?P<algorithm>md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?P<suffix>_[a-z0-9_]+)?$",
    re.IGNORECASE,
)
QUOTED_VALUE_RE = re.compile(r"""(['"])(.*?)\1""")
CHECKSUM_STRENGTH = {
    "md5": 1,
    "sha1": 2,
    "sha224": 3,
    "sha256": 4,
    "sha384": 5,
    "sha512": 6,
    "b2": 7,
}
VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


@dataclass(frozen=True)
class DiffValue:
    name: str
    value: str
    index: int
    line_number: int
    line_content: str
    filename: str | None


@dataclass(frozen=True)
class DiffArray:
    name: str
    sign: str
    filename: str | None
    line_number: int
    line_content: str
    values: tuple[DiffValue, ...]

    @property
    def suffix(self) -> str:
        source_match = SOURCE_ARRAY_RE.match(self.name)
        if source_match:
            return source_match.group("suffix") or ""

        checksum_match = CHECKSUM_ARRAY_RE.match(self.name)
        if checksum_match:
            return checksum_match.group("suffix") or ""

        return ""

    @property
    def checksum_algorithm(self) -> str | None:
        checksum_match = CHECKSUM_ARRAY_RE.match(self.name)
        if checksum_match:
            return checksum_match.group("algorithm").lower()
        return None


@dataclass(frozen=True)
class DiffArrays:
    removed: tuple[DiffArray, ...]
    added: tuple[DiffArray, ...]
    old_state: tuple[DiffArray, ...]
    new_state: tuple[DiffArray, ...]

    @property
    def removed_values(self) -> list[DiffValue]:
        return [value for array in self.removed for value in array.values]

    @property
    def added_values(self) -> list[DiffValue]:
        return [value for array in self.added for value in array.values]


@dataclass
class ArrayBlock:
    name: str
    sign: str
    filename: str | None
    start_line_number: int
    start_line_content: str
    lines: list[tuple[int, str]]
    changed: bool = False


def analyze_source_diff(text: str) -> list[Finding]:
    arrays = _collect_diff_arrays(text)
    findings: list[Finding] = []

    findings.extend(_compare_source_urls(arrays.removed_values, arrays.added_values))
    findings.extend(_find_removed_checksum_arrays(arrays))
    findings.extend(_find_checksum_algorithm_weakening(arrays))
    findings.extend(_find_checksum_count_mismatches(arrays))
    findings.extend(_find_added_checksum_skips(arrays))

    return findings


def _collect_diff_arrays(text: str) -> DiffArrays:
    removed: list[DiffArray] = []
    added: list[DiffArray] = []
    old_state: list[DiffArray] = []
    new_state: list[DiffArray] = []
    current_filename: str | None = None
    old_line_number: int | None = None
    new_line_number: int | None = None
    active_blocks: dict[str, ArrayBlock | None] = {"-": None, "+": None}

    for raw_line in text.splitlines():
        if raw_line.startswith("diff --git "):
            current_filename = None
            old_line_number = None
            new_line_number = None
            active_blocks = {"-": None, "+": None}
            continue

        if raw_line.startswith("+++"):
            current_filename = _filename_from_diff_header(raw_line)
            continue

        hunk_match = HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            old_line_number = int(hunk_match.group(1))
            new_line_number = int(hunk_match.group(2))
            active_blocks = {"-": None, "+": None}
            continue

        if old_line_number is None or new_line_number is None:
            continue

        if raw_line.startswith("\\"):
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            content = raw_line[1:]
            _consume_changed_line(
                content,
                "-",
                current_filename,
                old_line_number,
                active_blocks,
                removed,
                old_state,
            )
            old_line_number += 1
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:]
            _consume_changed_line(
                content,
                "+",
                current_filename,
                new_line_number,
                active_blocks,
                added,
                new_state,
            )
            new_line_number += 1
            continue

        content = raw_line[1:] if raw_line.startswith(" ") else raw_line
        _consume_context_line(
            content,
            current_filename,
            old_line_number,
            new_line_number,
            active_blocks,
            removed,
            added,
            old_state,
            new_state,
        )
        old_line_number += 1
        new_line_number += 1

    return DiffArrays(
        removed=tuple(removed),
        added=tuple(added),
        old_state=tuple(old_state),
        new_state=tuple(new_state),
    )


def _consume_changed_line(
    content: str,
    sign: str,
    filename: str | None,
    line_number: int,
    active_blocks: dict[str, ArrayBlock | None],
    changed_arrays: list[DiffArray],
    state_arrays: list[DiffArray],
) -> None:
    if not _is_pkgbuild(filename):
        return

    active_block = active_blocks[sign]
    if active_block is not None:
        active_block.lines.append((line_number, content))
        active_block.changed = True
        if ")" in content:
            array = _array_from_block(active_block)
            changed_arrays.append(array)
            state_arrays.append(array)
            active_blocks[sign] = None
        return

    match = ARRAY_START_RE.match(content)
    if not match:
        return

    name = match.group(1)
    rest = match.group(2)
    block = ArrayBlock(
        name=name,
        sign=sign,
        filename=filename,
        start_line_number=line_number,
        start_line_content=content,
        lines=[(line_number, content)],
    )

    if "(" in rest and ")" not in rest:
        active_blocks[sign] = block
        return

    array = _array_from_block(block)
    changed_arrays.append(array)
    state_arrays.append(array)


def _consume_context_line(
    content: str,
    filename: str | None,
    old_line_number: int,
    new_line_number: int,
    active_blocks: dict[str, ArrayBlock | None],
    removed: list[DiffArray],
    added: list[DiffArray],
    old_state: list[DiffArray],
    new_state: list[DiffArray],
) -> None:
    if not _is_pkgbuild(filename):
        active_blocks["-"] = None
        active_blocks["+"] = None
        return

    for sign, changed_arrays, state_arrays, line_number in (
        ("-", removed, old_state, old_line_number),
        ("+", added, new_state, new_line_number),
    ):
        active_block = active_blocks[sign]
        if active_block is not None:
            active_block.lines.append((line_number, content))
            if ")" in content:
                array = _array_from_block(active_block)
                if active_block.changed:
                    changed_arrays.append(array)
                state_arrays.append(array)
                active_blocks[sign] = None
            continue

        match = ARRAY_START_RE.match(content)
        if not match:
            continue

        rest = match.group(2)
        if "(" in rest and ")" not in rest:
            active_blocks[sign] = ArrayBlock(
                name=match.group(1),
                sign=sign,
                filename=filename,
                start_line_number=line_number,
                start_line_content=content,
                lines=[],
            )
            continue

        block = ArrayBlock(
            name=match.group(1),
            sign=sign,
            filename=filename,
            start_line_number=line_number,
            start_line_content=content,
            lines=[(line_number, content)],
        )
        state_arrays.append(_array_from_block(block))


def _array_from_block(block: ArrayBlock) -> DiffArray:
    values: list[DiffValue] = []
    for line_number, content in block.lines:
        for match in QUOTED_VALUE_RE.finditer(content):
            values.append(
                DiffValue(
                    name=block.name,
                    value=match.group(2),
                    index=len(values),
                    line_number=line_number,
                    line_content=content,
                    filename=block.filename,
                )
            )
    return DiffArray(
        name=block.name,
        sign=block.sign,
        filename=block.filename,
        line_number=block.start_line_number,
        line_content=block.start_line_content,
        values=tuple(values),
    )


def _compare_source_urls(
    removed: list[DiffValue],
    added: list[DiffValue],
) -> list[Finding]:
    old_urls = [value for value in removed if _is_source_url(value)]
    new_urls = [value for value in added if _is_source_url(value)]
    findings: list[Finding] = []

    for index, new_url in enumerate(new_urls):
        old_url = old_urls[index] if index < len(old_urls) else None
        if old_url is None:
            findings.append(
                _finding(
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
                _finding(
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
                _finding(
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


def _find_removed_checksum_arrays(arrays: DiffArrays) -> list[Finding]:
    findings: list[Finding] = []
    new_checksums_by_suffix = _checksum_arrays_by_suffix(arrays.new_state)

    for old_array in arrays.removed:
        if not _is_checksum_array(old_array):
            continue
        if old_array.suffix in new_checksums_by_suffix:
            continue
        findings.append(
            _array_finding(
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


def _find_checksum_algorithm_weakening(arrays: DiffArrays) -> list[Finding]:
    findings: list[Finding] = []
    old_checksums = _checksum_arrays_by_suffix(arrays.old_state)
    changed_new_checksums = _checksum_arrays_by_suffix(arrays.added)

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
            _array_finding(
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


def _find_checksum_count_mismatches(arrays: DiffArrays) -> list[Finding]:
    findings: list[Finding] = []
    source_arrays = _source_arrays_by_suffix(arrays.new_state)
    checksum_arrays = _checksum_arrays_by_suffix(arrays.new_state)

    for suffix, source_array in source_arrays.items():
        checksum_array = checksum_arrays.get(suffix)
        if checksum_array is None:
            continue
        if not source_array.values or not checksum_array.values:
            continue
        if len(source_array.values) == len(checksum_array.values):
            continue

        findings.append(
            _array_finding(
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


def _find_added_checksum_skips(arrays: DiffArrays) -> list[Finding]:
    old_checksums_by_suffix = _checksum_arrays_by_suffix(arrays.old_state)
    new_sources_by_suffix = _source_arrays_by_suffix(arrays.new_state)
    findings: list[Finding] = []

    for new_value in (value for value in arrays.added_values if _is_checksum(value)):
        old_value = _old_checksum_value(new_value, old_checksums_by_suffix)
        if new_value.value == "SKIP" and old_value != "SKIP":
            source_value = _source_for_checksum_value(new_value, new_sources_by_suffix)
            severity = Severity.MEDIUM if _is_vcs_source(source_value) else Severity.HIGH
            findings.append(
                _finding(
                    rule_id="checksum-skip-added",
                    severity=severity,
                    message="Checksum SKIP added",
                    hint=_checksum_skip_hint(severity),
                    value=new_value,
                    old_value=old_value,
                    new_value=new_value.value,
                )
            )

    return findings


def _array_finding(
    *,
    rule_id: str,
    severity: Severity,
    message: str,
    hint: str,
    array: DiffArray,
    old_value: str | None,
    new_value: str | None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        line_number=array.line_number,
        line_content=array.line_content,
        hint=hint,
        filename=array.filename,
        source_type="diff",
        target_line_number=array.line_number,
        change_type="added" if array.sign == "+" else "removed",
        old_value=old_value,
        new_value=new_value,
    )


def _finding(
    *,
    rule_id: str,
    severity: Severity,
    message: str,
    hint: str,
    value: DiffValue,
    old_value: str | None,
    new_value: str | None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        line_number=value.line_number,
        line_content=value.line_content,
        hint=hint,
        filename=value.filename,
        source_type="diff",
        target_line_number=value.line_number,
        change_type="added",
        old_value=old_value,
        new_value=new_value,
    )


def _filename_from_diff_header(line: str) -> str | None:
    parts = line.split(maxsplit=2)
    if len(parts) < 2:
        return None

    path = parts[1]
    if path == "/dev/null":
        return None
    if path.startswith("b/"):
        return path[2:]
    return path


def _is_pkgbuild(filename: str | None) -> bool:
    return filename == "PKGBUILD" or bool(filename and filename.endswith("/PKGBUILD"))


def _is_source_url(value: DiffValue) -> bool:
    parsed = urlparse(value.value)
    return SOURCE_ARRAY_RE.match(value.name) is not None and parsed.scheme in {"http", "https"}


def _is_checksum(value: DiffValue) -> bool:
    return value.name.lower() != "source" and value.value != ""


def _is_source_array(array: DiffArray) -> bool:
    return SOURCE_ARRAY_RE.match(array.name) is not None


def _is_checksum_array(array: DiffArray) -> bool:
    return CHECKSUM_ARRAY_RE.match(array.name) is not None


def _source_arrays_by_suffix(arrays: tuple[DiffArray, ...]) -> dict[str, DiffArray]:
    return {
        array.suffix: array
        for array in arrays
        if _is_source_array(array)
    }


def _checksum_arrays_by_suffix(arrays: tuple[DiffArray, ...]) -> dict[str, DiffArray]:
    return {
        array.suffix: array
        for array in arrays
        if _is_checksum_array(array)
    }


def _source_for_checksum_value(
    checksum_value: DiffValue,
    sources_by_suffix: dict[str, DiffArray],
) -> str | None:
    checksum_suffix = _array_suffix(checksum_value.name)
    source_array = sources_by_suffix.get(checksum_suffix)
    if source_array is None:
        return None

    if checksum_value.index >= len(source_array.values):
        return None
    return source_array.values[checksum_value.index].value


def _old_checksum_value(
    checksum_value: DiffValue,
    checksums_by_suffix: dict[str, DiffArray],
) -> str | None:
    old_array = checksums_by_suffix.get(_array_suffix(checksum_value.name))
    if old_array is None or checksum_value.index >= len(old_array.values):
        return None
    return old_array.values[checksum_value.index].value


def _array_suffix(name: str) -> str:
    source_match = SOURCE_ARRAY_RE.match(name)
    if source_match:
        return source_match.group("suffix") or ""

    checksum_match = CHECKSUM_ARRAY_RE.match(name)
    if checksum_match:
        return checksum_match.group("suffix") or ""

    return ""


def _is_vcs_source(source: str | None) -> bool:
    if source is None:
        return False
    lowered = source.lower()
    return lowered.startswith(VCS_PREFIXES) or urlparse(lowered).path.endswith(".git")


def _checksum_skip_hint(severity: Severity) -> str:
    if severity == Severity.MEDIUM:
        return "SKIP is common for VCS sources, but the source should still be reviewed."
    return "A newly skipped checksum weakens source verification."
