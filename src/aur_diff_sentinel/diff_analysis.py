from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from aur_diff_sentinel.models import Finding, Severity


HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
ARRAY_START_RE = re.compile(
    r"^\s*(source|(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[a-z0-9_]+)?)\s*=\s*(.*)$",
    re.IGNORECASE,
)
QUOTED_VALUE_RE = re.compile(r"""(['"])(.*?)\1""")


@dataclass(frozen=True)
class DiffValue:
    name: str
    value: str
    line_number: int
    line_content: str
    filename: str | None


@dataclass
class ArrayBlock:
    name: str
    sign: str
    filename: str | None
    start_line_number: int
    lines: list[tuple[int, str]]


def analyze_source_diff(text: str) -> list[Finding]:
    removed, added = _collect_diff_values(text)
    findings: list[Finding] = []

    findings.extend(_compare_source_urls(removed, added))
    findings.extend(_find_added_checksum_skips(removed, added))

    return findings


def _collect_diff_values(text: str) -> tuple[list[DiffValue], list[DiffValue]]:
    removed: list[DiffValue] = []
    added: list[DiffValue] = []
    current_filename: str | None = None
    target_line_number: int | None = None
    active_blocks: dict[str, ArrayBlock | None] = {"-": None, "+": None}

    for raw_line in text.splitlines():
        if raw_line.startswith("diff --git "):
            current_filename = None
            target_line_number = None
            active_blocks = {"-": None, "+": None}
            continue

        if raw_line.startswith("+++"):
            current_filename = _filename_from_diff_header(raw_line)
            continue

        hunk_match = HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            target_line_number = int(hunk_match.group(1))
            active_blocks = {"-": None, "+": None}
            continue

        if target_line_number is None:
            continue

        if raw_line.startswith("\\"):
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            content = raw_line[1:]
            _consume_changed_line(
                content,
                "-",
                current_filename,
                target_line_number,
                active_blocks,
                removed,
            )
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:]
            _consume_changed_line(
                content,
                "+",
                current_filename,
                target_line_number,
                active_blocks,
                added,
            )
            target_line_number += 1
            continue

        content = raw_line[1:] if raw_line.startswith(" ") else raw_line
        _consume_context_line(
            content,
            current_filename,
            target_line_number,
            active_blocks,
            removed,
            added,
        )
        target_line_number += 1

    return removed, added


def _consume_changed_line(
    content: str,
    sign: str,
    filename: str | None,
    line_number: int,
    active_blocks: dict[str, ArrayBlock | None],
    values: list[DiffValue],
) -> None:
    if not _is_pkgbuild(filename):
        return

    active_block = active_blocks[sign]
    if active_block is not None:
        active_block.lines.append((line_number, content))
        if ")" in content:
            values.extend(_values_from_block(active_block))
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
        lines=[(line_number, content)],
    )

    if "(" in rest and ")" not in rest:
        active_blocks[sign] = block
        return

    values.extend(_values_from_block(block))


def _consume_context_line(
    content: str,
    filename: str | None,
    line_number: int,
    active_blocks: dict[str, ArrayBlock | None],
    removed: list[DiffValue],
    added: list[DiffValue],
) -> None:
    if not _is_pkgbuild(filename):
        active_blocks["-"] = None
        active_blocks["+"] = None
        return

    for sign, values in (("-", removed), ("+", added)):
        active_block = active_blocks[sign]
        if active_block is not None:
            if ")" in content:
                values.extend(_values_from_block(active_block))
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
                lines=[],
            )


def _values_from_block(block: ArrayBlock) -> list[DiffValue]:
    values: list[DiffValue] = []
    for line_number, content in block.lines:
        for match in QUOTED_VALUE_RE.finditer(content):
            values.append(
                DiffValue(
                    name=block.name,
                    value=match.group(2),
                    line_number=line_number,
                    line_content=content,
                    filename=block.filename,
                )
            )
    return values


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


def _find_added_checksum_skips(
    removed: list[DiffValue],
    added: list[DiffValue],
) -> list[Finding]:
    old_checksum_values = [value.value for value in removed if _is_checksum(value)]
    findings: list[Finding] = []

    for index, new_value in enumerate(value for value in added if _is_checksum(value)):
        old_value = old_checksum_values[index] if index < len(old_checksum_values) else None
        if new_value.value == "SKIP" and old_value != "SKIP":
            findings.append(
                _finding(
                    rule_id="checksum-skip-added",
                    severity=Severity.HIGH,
                    message="Checksum SKIP added",
                    hint="A newly skipped checksum weakens source verification.",
                    value=new_value,
                    old_value=old_value,
                    new_value=new_value.value,
                )
            )

    return findings


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
    return value.name.lower() == "source" and parsed.scheme in {"http", "https"}


def _is_checksum(value: DiffValue) -> bool:
    return value.name.lower() != "source" and value.value != ""
