from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlparse


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


def collect_diff_arrays(text: str) -> DiffArrays:
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
            current_filename = filename_from_diff_header(raw_line)
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
    if not is_pkgbuild(filename):
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
    if not is_pkgbuild(filename):
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


def filename_from_diff_header(line: str) -> str | None:
    parts = line.split(maxsplit=2)
    if len(parts) < 2:
        return None

    path = parts[1]
    if path == "/dev/null":
        return None
    if path.startswith("b/"):
        return path[2:]
    return path


def is_pkgbuild(filename: str | None) -> bool:
    return filename == "PKGBUILD" or bool(filename and filename.endswith("/PKGBUILD"))


def is_source_url(value: DiffValue) -> bool:
    parsed = urlparse(value.value)
    return SOURCE_ARRAY_RE.match(value.name) is not None and parsed.scheme in {"http", "https"}


def is_checksum(value: DiffValue) -> bool:
    return CHECKSUM_ARRAY_RE.match(value.name) is not None and value.value != ""


def is_dependency(value: DiffValue) -> bool:
    return DEPENDENCY_ARRAY_RE.match(value.name) is not None and value.value != ""


def is_source_array(array: DiffArray) -> bool:
    return SOURCE_ARRAY_RE.match(array.name) is not None


def is_checksum_array(array: DiffArray) -> bool:
    return CHECKSUM_ARRAY_RE.match(array.name) is not None


def source_arrays_by_suffix(arrays: tuple[DiffArray, ...]) -> dict[str, DiffArray]:
    return {
        array.suffix: array
        for array in arrays
        if is_source_array(array)
    }


def checksum_arrays_by_suffix(arrays: tuple[DiffArray, ...]) -> dict[str, DiffArray]:
    return {
        array.suffix: array
        for array in arrays
        if is_checksum_array(array)
    }


def dependency_values_by_name(arrays: tuple[DiffArray, ...]) -> dict[str, list[DiffValue]]:
    dependencies: dict[str, list[DiffValue]] = {}
    for array in arrays:
        if not DEPENDENCY_ARRAY_RE.match(array.name):
            continue
        dependencies.setdefault(dependency_group(array.name), []).extend(array.values)
    return dependencies


def dependency_group_for(
    dependency: str,
    dependencies: dict[str, list[DiffValue]],
) -> str | None:
    for group, values in dependencies.items():
        if any(dependency_name(value.value) == dependency for value in values):
            return group
    return None


def dependency_name(value: str) -> str:
    return value.split(":", maxsplit=1)[0].split("<", maxsplit=1)[0].split(">", maxsplit=1)[0].split("=", maxsplit=1)[0].strip()


def dependency_group(name: str) -> str:
    match = DEPENDENCY_ARRAY_RE.match(name)
    if match:
        return match.group("group").lower()
    return name.lower()


def source_for_checksum_value(
    checksum_value: DiffValue,
    sources_by_suffix: dict[str, DiffArray],
) -> str | None:
    checksum_suffix = array_suffix(checksum_value.name)
    source_array = sources_by_suffix.get(checksum_suffix)
    if source_array is None:
        return None

    if checksum_value.index >= len(source_array.values):
        return None
    return source_array.values[checksum_value.index].value


def old_checksum_value(
    checksum_value: DiffValue,
    checksums_by_suffix: dict[str, DiffArray],
) -> str | None:
    old_array = checksums_by_suffix.get(array_suffix(checksum_value.name))
    if old_array is None or checksum_value.index >= len(old_array.values):
        return None
    return old_array.values[checksum_value.index].value


def array_suffix(name: str) -> str:
    source_match = SOURCE_ARRAY_RE.match(name)
    if source_match:
        return source_match.group("suffix") or ""

    checksum_match = CHECKSUM_ARRAY_RE.match(name)
    if checksum_match:
        return checksum_match.group("suffix") or ""

    return ""


def is_vcs_source(source: str | None) -> bool:
    if source is None:
        return False
    lowered = source_without_alias(source).lower()
    return lowered.startswith(VCS_PREFIXES) or urlparse(lowered).path.endswith(".git")


def source_without_alias(source: str) -> str:
    if "::" not in source:
        return source
    return source.split("::", 1)[1]
