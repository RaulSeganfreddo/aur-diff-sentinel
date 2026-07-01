from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse


HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
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


def filename_from_diff_header(line: str) -> str | None:
    parts = line.split(maxsplit=2)
    if len(parts) < 2:
        return None

    path = parts[1]
    if path == "/dev/null":
        return None
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def is_pkgbuild(filename: str | None) -> bool:
    return filename == "PKGBUILD" or bool(filename and filename.endswith("/PKGBUILD"))


def is_source_name(name: str) -> bool:
    return SOURCE_ARRAY_RE.match(name) is not None


def is_checksum_name(name: str) -> bool:
    return CHECKSUM_ARRAY_RE.match(name) is not None


def is_dependency_name(name: str) -> bool:
    return DEPENDENCY_ARRAY_RE.match(name) is not None


def array_suffix(name: str) -> str:
    source_match = SOURCE_ARRAY_RE.match(name)
    if source_match:
        return source_match.group("suffix") or ""

    checksum_match = CHECKSUM_ARRAY_RE.match(name)
    if checksum_match:
        return checksum_match.group("suffix") or ""

    return ""


def checksum_algorithm(name: str) -> str | None:
    checksum_match = CHECKSUM_ARRAY_RE.match(name)
    if checksum_match:
        return checksum_match.group("algorithm").lower()
    return None


def dependency_group(name: str) -> str:
    match = DEPENDENCY_ARRAY_RE.match(name)
    if match:
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
    if "::" not in source:
        return source
    return source.split("::", 1)[1]


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


def has_unquoted_closing_paren(content: str) -> bool:
    return unquoted_closing_paren_index(content) is not None


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
