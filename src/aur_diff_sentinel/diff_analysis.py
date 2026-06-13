from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from aur_diff_sentinel.models import Finding, Severity


HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
ARRAY_START_RE = re.compile(
    r"^\s*(source(?:_[a-z0-9_]+)?|depends(?:_[a-z0-9_]+)?|makedepends(?:_[a-z0-9_]+)?|checkdepends(?:_[a-z0-9_]+)?|optdepends(?:_[a-z0-9_]+)?|(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[a-z0-9_]+)?)\s*(\+?=)\s*(.*)$",
    re.IGNORECASE,
)
SOURCE_ARRAY_RE = re.compile(r"^source(?P<suffix>_[a-z0-9_]+)?$", re.IGNORECASE)
DEPENDENCY_ARRAY_RE = re.compile(
    r"^(?P<group>depends|makedepends|checkdepends|optdepends)(?P<suffix>_[a-z0-9_]+)?$",
    re.IGNORECASE,
)
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
JS_TOOLING_DEPENDENCIES = {"bun", "npm", "nodejs", "yarn", "pnpm"}
ELF_MAGIC = b"\x7fELF"


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

    findings.extend(_find_added_metadata_files(text))
    findings.extend(_compare_source_urls(arrays.removed_values, arrays.added_values))
    findings.extend(_find_removed_checksum_arrays(arrays))
    findings.extend(_find_checksum_algorithm_weakening(arrays))
    findings.extend(_find_checksum_count_mismatches(arrays))
    findings.extend(_find_added_checksum_skips(arrays))
    findings.extend(_find_dependency_changes(arrays))
    findings.extend(_dedupe_srcinfo_dependency_findings(findings, _find_srcinfo_dependency_changes(text)))

    return findings


def analyze_metadata_tree_changes(old_dir: Path, new_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not new_dir.exists():
        return findings

    for path in sorted(new_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative_path = path.relative_to(new_dir)
        if ".git" in relative_path.parts:
            continue
        if (old_dir / relative_path).exists():
            continue
        try:
            with path.open("rb") as file:
                magic = file.read(len(ELF_MAGIC))
        except OSError:
            continue
        if magic != ELF_MAGIC:
            continue
        filename = relative_path.as_posix()
        findings.append(
            _metadata_file_finding(
                "aur-metadata-elf-added",
                Severity.HIGH,
                "ELF file added directly to AUR metadata",
                "Compiled binaries committed directly to AUR metadata should be reviewed carefully.",
                filename,
                line_content="<ELF binary>",
            )
        )

    return findings


def _find_added_metadata_files(text: str) -> list[Finding]:
    findings: list[Finding] = []
    current_old: str | None = None
    current_new: str | None = None
    current_new_file = False
    shell_file_reported = False

    for raw_line in text.splitlines():
        if raw_line.startswith("diff --git "):
            current_old = None
            current_new = None
            current_new_file = False
            shell_file_reported = False
            continue
        if raw_line.startswith("---"):
            current_old = _filename_from_diff_header(raw_line)
            continue
        if raw_line.startswith("+++"):
            current_new = _filename_from_diff_header(raw_line)
            current_new_file = current_old is None and current_new is not None
            if current_new_file and current_new is not None:
                if current_new.endswith(".install"):
                    findings.append(
                        _metadata_file_finding(
                            "install-script-added",
                            Severity.MEDIUM,
                            "Install script file added",
                            "Install scripts can run on the live system during install, upgrade, or removal.",
                            current_new,
                        )
                    )
                elif current_new.endswith(".hook"):
                    findings.append(
                        _metadata_file_finding(
                            "pacman-hook-added",
                            Severity.MEDIUM,
                            "Pacman hook file added",
                            "Pacman hooks can run automatically during package transactions.",
                            current_new,
                        )
                    )
            continue
        if not current_new_file or current_new is None or not raw_line.startswith("+"):
            continue
        content = raw_line[1:]
        if not shell_file_reported and (
            content.startswith("#!/bin/sh")
            or content.startswith("#!/usr/bin/sh")
            or content.startswith("#!/bin/bash")
            or content.startswith("#!/usr/bin/bash")
        ):
            findings.append(
                _metadata_file_finding(
                    "aur-metadata-executable-added",
                    Severity.MEDIUM,
                    "Executable script file added",
                    "New executable scripts in AUR metadata should be reviewed before updating.",
                    current_new,
                    line_content=content,
                )
            )
            shell_file_reported = True
        if content.startswith("\x7fELF"):
            findings.append(
                _metadata_file_finding(
                    "aur-metadata-elf-added",
                    Severity.HIGH,
                    "ELF file added directly to AUR metadata",
                    "Compiled binaries committed directly to AUR metadata should be reviewed carefully.",
                    current_new,
                    line_content=content,
                )
            )

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
        if _has_unquoted_closing_paren(content):
            array = _array_from_block(active_block)
            changed_arrays.append(array)
            state_arrays.append(array)
            active_blocks[sign] = None
        return

    match = ARRAY_START_RE.match(content)
    if not match:
        return

    name = match.group(1)
    rest = match.group(3)
    block = ArrayBlock(
        name=name,
        sign=sign,
        filename=filename,
        start_line_number=line_number,
        start_line_content=content,
        lines=[(line_number, content)],
    )

    if "(" in rest and not _has_unquoted_closing_paren(rest):
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
            if _has_unquoted_closing_paren(content):
                array = _array_from_block(active_block)
                if active_block.changed:
                    changed_arrays.append(array)
                state_arrays.append(array)
                active_blocks[sign] = None
            continue

        match = ARRAY_START_RE.match(content)
        if not match:
            continue

        rest = match.group(3)
        if "(" in rest and not _has_unquoted_closing_paren(rest):
            active_blocks[sign] = ArrayBlock(
                name=match.group(1),
                sign=sign,
                filename=filename,
                start_line_number=line_number,
                start_line_content=content,
                lines=[(line_number, content)],
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
        for token in _array_values_from_line(content):
            values.append(
                DiffValue(
                    name=block.name,
                    value=token,
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


def _array_values_from_line(content: str) -> list[str]:
    value_text = _array_value_text(content)
    if not value_text:
        return []
    try:
        return shlex.split(value_text, comments=True, posix=True)
    except ValueError:
        return [match.group(2) for match in QUOTED_VALUE_RE.finditer(value_text)]


def _array_value_text(content: str) -> str:
    assignment = ARRAY_START_RE.match(content)
    if assignment:
        content = assignment.group(3)
    content = content.strip()
    if content.startswith("("):
        content = content[1:]
    closing_paren_index = _unquoted_closing_paren_index(content)
    if closing_paren_index is not None:
        content = content[:closing_paren_index]
    return content.strip()


def _has_unquoted_closing_paren(content: str) -> bool:
    return _unquoted_closing_paren_index(content) is not None


def _unquoted_closing_paren_index(content: str) -> int | None:
    quote: str | None = None
    escape = False
    for index, char in enumerate(content):
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == ")":
            return index
    return None


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


def _find_dependency_changes(arrays: DiffArrays) -> list[Finding]:
    findings: list[Finding] = []
    old_dependencies = _dependency_values_by_name(arrays.old_state)
    new_dependencies = _dependency_values_by_name(arrays.new_state)
    old_all = {dependency_name(value.value) for values in old_dependencies.values() for value in values}
    new_all = {dependency_name(value.value) for values in new_dependencies.values() for value in values}

    for value in arrays.added_values:
        if not _is_dependency(value):
            continue
        name = dependency_name(value.value)
        if name in old_all:
            if _dependency_group_for(name, old_dependencies) != _dependency_group(value.name):
                findings.append(
                    _finding(
                        rule_id="dependency-moved",
                        severity=Severity.LOW,
                        message=f"Dependency moved to {value.name}",
                        hint="Dependency group changes should be checked for packaging intent.",
                        value=value,
                        old_value=_dependency_group_for(name, old_dependencies),
                        new_value=_dependency_group(value.name),
                    )
                )
            continue
        if name in JS_TOOLING_DEPENDENCIES:
            findings.append(
                _finding(
                    rule_id="javascript-tooling-dependency-added",
                    severity=Severity.MEDIUM,
                    message=f"JavaScript tooling dependency added to {_dependency_group(value.name)}: {name}",
                    hint="New JavaScript tooling dependencies can be legitimate, but should be reviewed with install scripts and hooks.",
                    value=value,
                    old_value=None,
                    new_value=name,
                )
            )

    for value in arrays.removed_values:
        if not _is_dependency(value):
            continue
        name = dependency_name(value.value)
        if name in new_all:
            continue
        findings.append(
            _finding(
                rule_id="dependency-removed",
                severity=Severity.LOW,
                message=f"Dependency removed: {name}",
                hint="Removed dependencies may be normal packaging churn, but can change review context.",
                value=value,
                old_value=name,
                new_value=None,
            )
        )

    return findings


def _find_srcinfo_dependency_changes(text: str) -> list[Finding]:
    added: list[DiffValue] = []
    removed_names: set[str] = set()
    current_filename: str | None = None
    old_line_number: int | None = None
    new_line_number: int | None = None

    for raw_line in text.splitlines():
        if raw_line.startswith("diff --git "):
            current_filename = None
            old_line_number = None
            new_line_number = None
            continue
        if raw_line.startswith("+++"):
            current_filename = _filename_from_diff_header(raw_line)
            continue
        hunk_match = HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            old_line_number = int(hunk_match.group(1))
            new_line_number = int(hunk_match.group(2))
            continue
        if old_line_number is None or new_line_number is None:
            continue
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            value = _srcinfo_dependency_value(raw_line[1:], current_filename)
            if value is not None:
                removed_names.add(dependency_name(value.value))
            old_line_number += 1
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            value = _srcinfo_dependency_value(raw_line[1:], current_filename, new_line_number)
            if value is not None:
                added.append(value)
            new_line_number += 1
            continue
        old_line_number += 1
        new_line_number += 1

    findings: list[Finding] = []
    for value in added:
        name = dependency_name(value.value)
        if name in removed_names or name not in JS_TOOLING_DEPENDENCIES:
            continue
        findings.append(
            _finding(
                rule_id="javascript-tooling-dependency-added",
                severity=Severity.MEDIUM,
                message=f"JavaScript tooling dependency added to {_dependency_group(value.name)}: {name}",
                hint="New JavaScript tooling dependencies can be legitimate, but should be reviewed with install scripts and hooks.",
                value=value,
                old_value=None,
                new_value=name,
            )
        )
    return findings


def _srcinfo_dependency_value(
    content: str,
    filename: str | None,
    line_number: int = 0,
) -> DiffValue | None:
    if filename != ".SRCINFO" and not (filename and filename.endswith("/.SRCINFO")):
        return None
    match = re.match(
        r"^\s*(depends(?:_[a-z0-9_]+)?|makedepends(?:_[a-z0-9_]+)?|checkdepends(?:_[a-z0-9_]+)?|optdepends(?:_[a-z0-9_]+)?)\s*=\s*(\S+)",
        content,
    )
    if not match:
        return None
    return DiffValue(
        name=match.group(1),
        value=match.group(2),
        index=0,
        line_number=line_number,
        line_content=content,
        filename=filename,
    )


def _dedupe_srcinfo_dependency_findings(
    existing: list[Finding],
    srcinfo_findings: list[Finding],
) -> list[Finding]:
    pkgbuild_dependency_values = {
        finding.new_value
        for finding in existing
        if finding.rule_id == "javascript-tooling-dependency-added"
        and (finding.filename == "PKGBUILD" or bool(finding.filename and finding.filename.endswith("/PKGBUILD")))
    }
    return [
        finding
        for finding in srcinfo_findings
        if finding.new_value not in pkgbuild_dependency_values
    ]


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


def _metadata_file_finding(
    rule_id: str,
    severity: Severity,
    message: str,
    hint: str,
    filename: str,
    *,
    line_content: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        line_number=1,
        line_content=line_content or filename,
        hint=hint,
        filename=filename,
        source_type="diff",
        target_line_number=1,
        change_type="added",
        new_value=filename,
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
    return CHECKSUM_ARRAY_RE.match(value.name) is not None and value.value != ""


def _is_dependency(value: DiffValue) -> bool:
    return DEPENDENCY_ARRAY_RE.match(value.name) is not None and value.value != ""


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


def _dependency_values_by_name(arrays: tuple[DiffArray, ...]) -> dict[str, list[DiffValue]]:
    dependencies: dict[str, list[DiffValue]] = {}
    for array in arrays:
        if not DEPENDENCY_ARRAY_RE.match(array.name):
            continue
        dependencies.setdefault(_dependency_group(array.name), []).extend(array.values)
    return dependencies


def _dependency_group_for(
    dependency: str,
    dependencies: dict[str, list[DiffValue]],
) -> str | None:
    for group, values in dependencies.items():
        if any(dependency_name(value.value) == dependency for value in values):
            return group
    return None


def dependency_name(value: str) -> str:
    return value.split(":", maxsplit=1)[0].split("<", maxsplit=1)[0].split(">", maxsplit=1)[0].split("=", maxsplit=1)[0].strip()


def _dependency_group(name: str) -> str:
    match = DEPENDENCY_ARRAY_RE.match(name)
    if match:
        return match.group("group").lower()
    return name.lower()


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
    lowered = _source_without_alias(source).lower()
    return lowered.startswith(VCS_PREFIXES) or urlparse(lowered).path.endswith(".git")


def _source_without_alias(source: str) -> str:
    if "::" not in source:
        return source
    return source.split("::", 1)[1]


def _checksum_skip_hint(severity: Severity) -> str:
    if severity == Severity.MEDIUM:
        return "SKIP is common for VCS sources, but the source should still be reviewed."
    return "A newly skipped checksum weakens source verification."
