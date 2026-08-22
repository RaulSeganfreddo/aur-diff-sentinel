from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Literal

from aur_diff_sentinel.pkgbuild_syntax import HUNK_HEADER_RE, filename_from_diff_header


ChangeType = Literal["added", "removed", "context"]


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
    old_filename: str | None = None
    new_filename: str | None = None
    has_new_header = False
    old_line_number: int | None = None
    new_line_number: int | None = None
    hunk_index = 0

    for diff_line_number, raw_line in enumerate(text.splitlines(), start=1):
        if raw_line.startswith("diff --git "):
            old_filename = new_filename = None
            has_new_header = False
            old_line_number = new_line_number = None
            continue

        if raw_line.startswith("---"):
            old_filename = filename_from_diff_header(raw_line)
            continue

        if raw_line.startswith("+++"):
            new_filename = filename_from_diff_header(raw_line)
            has_new_header = True
            continue

        hunk_match = HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            old_line_number = int(hunk_match.group(1))
            new_line_number = int(hunk_match.group(2))
            hunk_index += 1
            continue

        if old_line_number is None or new_line_number is None:
            continue

        if raw_line.startswith("\\"):
            continue

        diff_file = DiffFile(
            old_filename=old_filename,
            new_filename=new_filename if has_new_header else fallback_filename,
        )

        if raw_line.startswith(("-", "+")):
            added = raw_line.startswith("+")
            yield DiffLine(
                diff_line_number=diff_line_number,
                hunk_index=hunk_index,
                change_type="added" if added else "removed",
                content=raw_line[1:],
                file=diff_file,
                old_line_number=None if added else old_line_number,
                new_line_number=new_line_number if added else None,
            )
            if added:
                new_line_number += 1
            else:
                old_line_number += 1
            continue

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


def iter_diff_files(text: str) -> Iterator[DiffFile]:
    old_filename: str | None = None

    for raw_line in text.splitlines():
        if raw_line.startswith("diff --git "):
            old_filename = None
            continue
        if raw_line.startswith("---"):
            old_filename = filename_from_diff_header(raw_line)
            continue
        if raw_line.startswith("+++"):
            yield DiffFile(
                old_filename=old_filename,
                new_filename=filename_from_diff_header(raw_line),
            )
