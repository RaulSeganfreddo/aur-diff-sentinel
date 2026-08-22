from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, Literal

from aur_diff_sentinel.pkgbuild_syntax import filename_from_diff_header


ChangeType = Literal["added", "removed", "context"]
_HUNK_RANGE_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class DiffFile:
    old_filename: str | None
    new_filename: str | None

    @property
    def filename(self) -> str | None:
        return self.new_filename or self.old_filename

    @property
    def is_new_file(self) -> bool:
        return self.old_filename is None and self.new_filename is not None

    @property
    def is_deleted_file(self) -> bool:
        return self.old_filename is not None and self.new_filename is None


@dataclass(frozen=True)
class DiffLine:
    diff_line_number: int
    hunk_index: int
    change_type: ChangeType
    content: str
    file: DiffFile
    old_line_number: int | None = None
    new_line_number: int | None = None

    @property
    def filename(self) -> str | None:
        return self.file.filename

    @property
    def line_number(self) -> int:
        preferred = self.old_line_number if self.change_type == "removed" else self.new_line_number
        fallback = self.new_line_number if self.new_line_number is not None else self.old_line_number
        return preferred if preferred is not None else fallback or 0


def iter_diff_lines(text: str, *, fallback_filename: str | None = None) -> Iterator[DiffLine]:
    for event in _iter_diff_events(text, fallback_filename=fallback_filename):
        if isinstance(event, DiffLine):
            yield event


def iter_diff_files(text: str) -> Iterator[DiffFile]:
    for event in _iter_diff_events(text):
        if isinstance(event, DiffFile):
            yield event


def _iter_diff_events(
    text: str,
    *,
    fallback_filename: str | None = None,
) -> Iterator[DiffFile | DiffLine]:
    old_filename: str | None = None
    new_filename: str | None = None
    has_new_header = False
    old_line_number: int | None = None
    new_line_number: int | None = None
    old_lines_remaining = 0
    new_lines_remaining = 0
    hunk_index = 0

    for diff_line_number, raw_line in enumerate(text.splitlines(), start=1):
        in_hunk = old_line_number is not None and new_line_number is not None
        if in_hunk:
            if raw_line.startswith("\\"):
                continue

            diff_file = DiffFile(
                old_filename=old_filename,
                new_filename=new_filename if has_new_header else fallback_filename,
            )
            if raw_line.startswith("+") and new_lines_remaining:
                yield DiffLine(
                    diff_line_number=diff_line_number,
                    hunk_index=hunk_index,
                    change_type="added",
                    content=raw_line[1:],
                    file=diff_file,
                    new_line_number=new_line_number,
                )
                new_line_number += 1
                new_lines_remaining -= 1
            elif raw_line.startswith("-") and old_lines_remaining:
                yield DiffLine(
                    diff_line_number=diff_line_number,
                    hunk_index=hunk_index,
                    change_type="removed",
                    content=raw_line[1:],
                    file=diff_file,
                    old_line_number=old_line_number,
                )
                old_line_number += 1
                old_lines_remaining -= 1
            elif old_lines_remaining and new_lines_remaining:
                content = raw_line[1:] if raw_line.startswith(" ") else raw_line
                yield DiffLine(
                    diff_line_number=diff_line_number,
                    hunk_index=hunk_index,
                    change_type="context",
                    content=content,
                    file=diff_file,
                    old_line_number=old_line_number,
                    new_line_number=new_line_number,
                )
                old_line_number += 1
                new_line_number += 1
                old_lines_remaining -= 1
                new_lines_remaining -= 1

            if not old_lines_remaining and not new_lines_remaining:
                old_line_number = new_line_number = None
            continue

        if raw_line.startswith("diff --git "):
            old_filename = new_filename = None
            has_new_header = False
            old_line_number = new_line_number = None
            continue

        if raw_line.startswith("--- "):
            old_filename = filename_from_diff_header(raw_line)
            new_filename = None
            has_new_header = False
            continue

        if raw_line.startswith("+++ "):
            new_filename = filename_from_diff_header(raw_line)
            has_new_header = True
            yield DiffFile(old_filename=old_filename, new_filename=new_filename)
            continue

        hunk_match = _HUNK_RANGE_RE.match(raw_line)
        if hunk_match:
            old_line_number = int(hunk_match.group(1))
            old_lines_remaining = int(hunk_match.group(2) or 1)
            new_line_number = int(hunk_match.group(3))
            new_lines_remaining = int(hunk_match.group(4) or 1)
            hunk_index += 1
            if not old_lines_remaining and not new_lines_remaining:
                old_line_number = new_line_number = None
            continue
