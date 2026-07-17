from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from aur_diff_sentinel.pkgbuild_syntax import (
    ArrayCollector,
    ArrayValue,
    ParsedArray,
    array_suffix,
    dependency_group,
    dependency_name,
    is_checksum_name,
    is_dependency_name,
    is_pkgbuild,
    is_source_name,
    merge_array_assignments,
    source_without_alias,
)
from aur_diff_sentinel.unified_diff import iter_diff_lines


DiffValue = ArrayValue
DiffArray = ParsedArray


@dataclass(frozen=True)
class DiffArrays:
    removed: tuple[ParsedArray, ...]
    added: tuple[ParsedArray, ...]
    old_state: tuple[ParsedArray, ...]
    new_state: tuple[ParsedArray, ...]

    @property
    def removed_values(self) -> list[ArrayValue]:
        return [value for array in self.removed for value in array.values]

    @property
    def added_values(self) -> list[ArrayValue]:
        return [value for array in self.added for value in array.values]

    def by_filename(self) -> tuple[DiffArrays, ...]:
        filenames = dict.fromkeys(
            array.filename
            for arrays in (self.old_state, self.new_state, self.removed, self.added)
            for array in arrays
        )
        return tuple(
            DiffArrays(
                removed=tuple(array for array in self.removed if array.filename == filename),
                added=tuple(array for array in self.added if array.filename == filename),
                old_state=tuple(array for array in self.old_state if array.filename == filename),
                new_state=tuple(array for array in self.new_state if array.filename == filename),
            )
            for filename in filenames
        )


def collect_diff_arrays(text: str) -> DiffArrays:
    changed: dict[str, list[ParsedArray]] = {"-": [], "+": []}
    states: dict[str, list[ParsedArray]] = {"-": [], "+": []}
    collectors = {"-": ArrayCollector(sign="-"), "+": ArrayCollector(sign="+")}
    current_hunk: int | None = None

    for line in iter_diff_lines(text):
        if line.hunk_index != current_hunk:
            for collector in collectors.values():
                collector.reset()
            current_hunk = line.hunk_index
        if not is_pkgbuild(line.filename):
            for collector in collectors.values():
                collector.reset()
            continue

        if line.change_type == "removed":
            _feed(
                collectors["-"], line.content, line.line_number, line.filename, True,
                changed["-"], states["-"],
            )
        elif line.change_type == "added":
            _feed(
                collectors["+"], line.content, line.line_number, line.filename, True,
                changed["+"], states["+"],
            )
        else:
            old_line = line.old_line_number if line.old_line_number is not None else line.line_number
            new_line = line.new_line_number if line.new_line_number is not None else line.line_number
            _feed(collectors["-"], line.content, old_line, line.filename, False, changed["-"], states["-"])
            _feed(collectors["+"], line.content, new_line, line.filename, False, changed["+"], states["+"])

    return DiffArrays(
        removed=tuple(changed["-"]),
        added=tuple(changed["+"]),
        old_state=tuple(states["-"]),
        new_state=tuple(states["+"]),
    )


def _feed(
    collector: ArrayCollector,
    content: str,
    line_number: int,
    filename: str | None,
    changed: bool,
    changed_arrays: list[ParsedArray],
    state_arrays: list[ParsedArray],
) -> None:
    array = collector.feed(
        content,
        line_number=line_number,
        filename=filename,
        changed=changed,
    )
    if array is None:
        return
    state_arrays.append(array)
    if array.changed:
        changed_arrays.append(array)


def is_source_url(value: ArrayValue) -> bool:
    parsed = urlparse(source_without_alias(value.value))
    return is_source_name(value.name) and parsed.scheme in {"http", "https"}


def is_checksum(value: ArrayValue) -> bool:
    return is_checksum_name(value.name) and bool(value.value)


def is_dependency(value: ArrayValue) -> bool:
    return is_dependency_name(value.name) and bool(value.value)


def is_source_array(array: ParsedArray) -> bool:
    return is_source_name(array.name)


def is_checksum_array(array: ParsedArray) -> bool:
    return is_checksum_name(array.name)


def source_arrays_by_suffix(arrays: tuple[ParsedArray, ...]) -> dict[str, ParsedArray]:
    return _arrays_by_suffix(arrays, source=True)


def checksum_arrays_by_suffix(arrays: tuple[ParsedArray, ...]) -> dict[str, ParsedArray]:
    return _arrays_by_suffix(arrays, source=False)


def _arrays_by_suffix(
    arrays: tuple[ParsedArray, ...],
    *,
    source: bool,
) -> dict[str, ParsedArray]:
    predicate = is_source_array if source else is_checksum_array
    return merge_array_assignments(
        (array for array in arrays if predicate(array)),
        key=lambda array: array.suffix.lower(),
    )


def dependency_values_by_name(arrays: tuple[ParsedArray, ...]) -> dict[str, list[ArrayValue]]:
    by_array = merge_array_assignments(
        (array for array in arrays if is_dependency_name(array.name)),
        key=lambda array: array.name.lower(),
    )
    dependencies: dict[str, list[ArrayValue]] = {}
    for array in by_array.values():
        dependencies.setdefault(dependency_group(array.name), []).extend(array.values)
    return dependencies


def dependency_group_for(
    dependency: str,
    dependencies: dict[str, list[ArrayValue]],
) -> str | None:
    for group, values in dependencies.items():
        if any(dependency_name(value.value) == dependency for value in values):
            return group
    return None


def source_for_checksum_value(
    checksum_value: ArrayValue,
    sources_by_suffix: dict[str, ParsedArray],
) -> str | None:
    source_array = sources_by_suffix.get(array_suffix(checksum_value.name).lower())
    if source_array is None or checksum_value.index >= len(source_array.values):
        return None
    return source_array.values[checksum_value.index].value


def old_checksum_value(
    checksum_value: ArrayValue,
    checksums_by_suffix: dict[str, ParsedArray],
) -> str | None:
    old_array = checksums_by_suffix.get(array_suffix(checksum_value.name).lower())
    if old_array is None or checksum_value.index >= len(old_array.values):
        return None
    return old_array.values[checksum_value.index].value
