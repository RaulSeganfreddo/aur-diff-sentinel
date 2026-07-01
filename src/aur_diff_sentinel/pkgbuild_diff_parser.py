from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from aur_diff_sentinel.pkgbuild_syntax import (
    array_suffix,
    array_value_text,
    checksum_algorithm,
    dependency_group,
    dependency_name,
    has_unquoted_closing_paren,
    is_checksum_name,
    is_dependency_name,
    is_pkgbuild,
    is_source_name,
    is_vcs_source,
    split_array_values,
)
from aur_diff_sentinel.unified_diff import iter_diff_lines


ARRAY_START_RE = re.compile(
    r"^\s*(source(?:_[a-z0-9_]+)?|depends(?:_[a-z0-9_]+)?|makedepends(?:_[a-z0-9_]+)?|checkdepends(?:_[a-z0-9_]+)?|optdepends(?:_[a-z0-9_]+)?|(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[a-z0-9_]+)?)\s*(\+?=)\s*(.*)$",
    re.IGNORECASE,
)


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
        return array_suffix(self.name)

    @property
    def checksum_algorithm(self) -> str | None:
        return checksum_algorithm(self.name)


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
    active_blocks: dict[str, ArrayBlock | None] = {"-": None, "+": None}
    current_hunk_index: int | None = None

    for line in iter_diff_lines(text):
        if line.hunk_index != current_hunk_index:
            active_blocks = {"-": None, "+": None}
            current_hunk_index = line.hunk_index

        if line.change_type == "removed":
            _consume_changed_line(
                line.content,
                "-",
                line.filename,
                line.line_number,
                active_blocks,
                removed,
                old_state,
            )
            continue

        if line.change_type == "added":
            _consume_changed_line(
                line.content,
                "+",
                line.filename,
                line.line_number,
                active_blocks,
                added,
                new_state,
            )
            continue

        _consume_context_line(
            line.content,
            line.filename,
            line.old_line_number or line.line_number,
            line.new_line_number or line.line_number,
            active_blocks,
            removed,
            added,
            old_state,
            new_state,
        )

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
        if has_unquoted_closing_paren(content):
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

    if "(" in rest and not has_unquoted_closing_paren(rest):
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
            if has_unquoted_closing_paren(content):
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
        if "(" in rest and not has_unquoted_closing_paren(rest):
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
    assignment = ARRAY_START_RE.match(content)
    value_content = assignment.group(3) if assignment else content
    value_text = array_value_text(value_content)
    if not value_text:
        return []
    return split_array_values(value_text, quoted_fallback=True)


def is_source_url(value: DiffValue) -> bool:
    parsed = urlparse(value.value)
    return is_source_name(value.name) and parsed.scheme in {"http", "https"}


def is_checksum(value: DiffValue) -> bool:
    return is_checksum_name(value.name) and value.value != ""


def is_dependency(value: DiffValue) -> bool:
    return is_dependency_name(value.name) and value.value != ""


def is_source_array(array: DiffArray) -> bool:
    return is_source_name(array.name)


def is_checksum_array(array: DiffArray) -> bool:
    return is_checksum_name(array.name)


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
        if not is_dependency_name(array.name):
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
