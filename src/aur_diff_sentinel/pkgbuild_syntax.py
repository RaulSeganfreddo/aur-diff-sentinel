from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass, replace
from typing import TypeVar
from urllib.parse import urlparse


HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
ARRAY_START_RE = re.compile(
    r"^\s*(source(?:_[a-z0-9_]+)?|depends(?:_[a-z0-9_]+)?|"
    r"makedepends(?:_[a-z0-9_]+)?|checkdepends(?:_[a-z0-9_]+)?|"
    r"optdepends(?:_[a-z0-9_]+)?|"
    r"(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[a-z0-9_]+)?)"
    r"\s*(\+?=)\s*(.*)$",
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
ArrayKey = TypeVar("ArrayKey", bound=Hashable)


@dataclass(frozen=True)
class ArrayValue:
    name: str
    value: str
    index: int
    line_number: int
    line_content: str
    filename: str | None = None
    sign: str = ""

    @property
    def suffix(self) -> str:
        return array_suffix(self.name)


@dataclass(frozen=True)
class ParsedArray:
    name: str
    operator: str
    filename: str | None
    line_number: int
    line_content: str
    values: tuple[ArrayValue, ...]
    sign: str = ""
    changed: bool = False

    @property
    def suffix(self) -> str:
        return array_suffix(self.name)

    @property
    def checksum_algorithm(self) -> str | None:
        return checksum_algorithm(self.name)


@dataclass
class _ArrayBlock:
    name: str
    operator: str
    filename: str | None
    line_number: int
    line_content: str
    lines: list[tuple[int, str]]
    sign: str
    changed: bool


class ArrayCollector:
    def __init__(self, *, sign: str = "") -> None:
        self.sign = sign
        self.active: _ArrayBlock | None = None

    def reset(self) -> None:
        self.active = None

    def feed(
        self,
        content: str,
        *,
        line_number: int,
        filename: str | None,
        changed: bool,
    ) -> ParsedArray | None:
        if self.active is not None:
            self.active.lines.append((line_number, content))
            self.active.changed |= changed
            if unquoted_closing_paren_index(content) is not None:
                return self._finish()
            return None

        match = ARRAY_START_RE.match(content)
        if match is None:
            return None
        block = _ArrayBlock(
            name=match.group(1),
            operator=match.group(2),
            filename=filename,
            line_number=line_number,
            line_content=content,
            lines=[(line_number, content)],
            sign=self.sign,
            changed=changed,
        )
        rest = match.group(3)
        if "(" in rest and unquoted_closing_paren_index(rest) is None:
            self.active = block
            return None
        return _parsed_array(block)

    def _finish(self) -> ParsedArray:
        block = self.active
        if block is None:
            raise RuntimeError("array collector has no active block")
        self.active = None
        return _parsed_array(block)


def collect_arrays_from_text(text: str, *, filename: str | None = None) -> list[ParsedArray]:
    collector = ArrayCollector()
    arrays: list[ParsedArray] = []
    for line_number, content in enumerate(text.splitlines(), start=1):
        array = collector.feed(
            content,
            line_number=line_number,
            filename=filename,
            changed=True,
        )
        if array is not None:
            arrays.append(array)
    return arrays


def merge_array_assignments(
    arrays: Iterable[ParsedArray],
    *,
    key: Callable[[ParsedArray], ArrayKey],
) -> dict[ArrayKey, ParsedArray]:
    merged: dict[ArrayKey, ParsedArray] = {}
    for array in arrays:
        array_key = key(array)
        previous = merged.get(array_key)
        if array.operator != "+=" or previous is None:
            merged[array_key] = array
            continue
        offset = len(previous.values)
        appended = tuple(replace(value, index=offset + value.index) for value in array.values)
        merged[array_key] = replace(array, values=(*previous.values, *appended))
    return merged


def _parsed_array(block: _ArrayBlock) -> ParsedArray:
    values: list[ArrayValue] = []
    for line_number, content in block.lines:
        assignment = ARRAY_START_RE.match(content)
        value_content = assignment.group(3) if assignment else content
        value_text = array_value_text(value_content)
        for token in split_array_values(value_text, quoted_fallback=True) if value_text else ():
            values.append(
                ArrayValue(
                    name=block.name,
                    value=token,
                    index=len(values),
                    line_number=line_number,
                    line_content=content,
                    filename=block.filename,
                    sign=block.sign,
                )
            )
    return ParsedArray(
        name=block.name,
        operator=block.operator,
        filename=block.filename,
        line_number=block.line_number,
        line_content=block.line_content,
        values=tuple(values),
        sign=block.sign,
        changed=block.changed,
    )


def filename_from_diff_header(line: str) -> str | None:
    parts = line.split()
    if len(parts) < 2 or parts[1] == "/dev/null":
        return None
    path = parts[1]
    return path[2:] if path.startswith(("a/", "b/")) else path


def is_pkgbuild(filename: str | None) -> bool:
    return filename == "PKGBUILD" or bool(filename and filename.endswith("/PKGBUILD"))


def is_source_name(name: str) -> bool:
    return SOURCE_ARRAY_RE.match(name) is not None


def is_checksum_name(name: str) -> bool:
    return CHECKSUM_ARRAY_RE.match(name) is not None


def is_dependency_name(name: str) -> bool:
    return DEPENDENCY_ARRAY_RE.match(name) is not None


def array_suffix(name: str) -> str:
    for pattern in (SOURCE_ARRAY_RE, CHECKSUM_ARRAY_RE):
        if match := pattern.match(name):
            return match.group("suffix") or ""
    return ""


def checksum_algorithm(name: str) -> str | None:
    if match := CHECKSUM_ARRAY_RE.match(name):
        return match.group("algorithm").lower()
    return None


def dependency_group(name: str) -> str:
    if match := DEPENDENCY_ARRAY_RE.match(name):
        return match.group("group").lower()
    return name.lower()


def dependency_name(value: str) -> str:
    return value.split(":", maxsplit=1)[0].split("<", maxsplit=1)[0].split(">", maxsplit=1)[0].split("=", maxsplit=1)[0].strip()


def is_vcs_source(source: str | None) -> bool:
    if source is None:
        return False
    lowered = source_without_alias(source).lower()
    return lowered.startswith(VCS_PREFIXES) or urlparse(lowered).path.endswith(".git")


def source_without_alias(source: str) -> str:
    alias, separator, value = source.partition("::")
    return value if separator else alias


def split_array_values(segment: str, *, quoted_fallback: bool = False) -> list[str]:
    try:
        return shlex.split(segment, comments=True, posix=True)
    except ValueError:
        if quoted_fallback:
            return [match.group(2) for match in QUOTED_VALUE_RE.finditer(segment)]
        return []


def array_value_text(content: str) -> str:
    content = content.strip()
    if content.startswith("("):
        content = content[1:]
    closing_paren_index = unquoted_closing_paren_index(content)
    if closing_paren_index is not None:
        content = content[:closing_paren_index]
    return content.strip()


def unquoted_closing_paren_index(content: str) -> int | None:
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
