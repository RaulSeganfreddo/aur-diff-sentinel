from __future__ import annotations

import re
from collections.abc import Collection

from aur_diff_sentinel.models import SourceLine
from aur_diff_sentinel.unified_diff import iter_diff_lines


BUILD_FUNCTIONS = {"prepare", "build", "check", "package"}
SCRIPTLET_FUNCTIONS = {
    "pre_install",
    "post_install",
    "pre_upgrade",
    "post_upgrade",
    "pre_remove",
    "post_remove",
}
FUNCTION_START_RE = re.compile(
    r"^\s*(?:function\s+)?"
    r"(prepare|build|check|package|pre_install|post_install|pre_upgrade|post_upgrade|pre_remove|post_remove)"
    r"\s*(?:\(\s*\))?\s*\{"
)


def is_full_line_comment(content: str) -> bool:
    return content.lstrip().startswith("#")


def source_lines_from_text(
    text: str,
    filename: str | None = None,
    *,
    scriptlet_files: Collection[str] | None = None,
) -> list[SourceLine]:
    tracker = FunctionContextTracker(filename, scriptlet_files=scriptlet_files)
    lines: list[SourceLine] = []

    for index, line in enumerate(text.splitlines(), start=1):
        function_name, execution_context = tracker.annotate(line)
        lines.append(
            SourceLine(
                line_number=index,
                content=line,
                filename=filename,
                source_type="file",
                function_name=function_name,
                execution_context=execution_context,
            )
        )

    return lines


def source_lines_from_diff(
    text: str,
    filename: str | None = None,
    *,
    scriptlet_files: Collection[str] | None = None,
) -> list[SourceLine]:
    lines: list[SourceLine] = []
    tracker = FunctionContextTracker(filename, scriptlet_files=scriptlet_files)
    current_hunk_index: int | None = None

    for line in iter_diff_lines(text, fallback_filename=filename):
        if line.filename != tracker.filename or line.hunk_index != current_hunk_index:
            tracker = FunctionContextTracker(line.filename, scriptlet_files=scriptlet_files)
            current_hunk_index = line.hunk_index
        if line.change_type == "added":
            function_name, execution_context = tracker.annotate(line.content)
            lines.append(
                SourceLine(
                    line_number=line.line_number,
                    content=line.content,
                    filename=line.filename,
                    source_type="diff",
                    diff_line_number=line.diff_line_number,
                    target_line_number=line.new_line_number,
                    change_type="added",
                    function_name=function_name,
                    execution_context=execution_context,
                )
            )
            continue

        if line.change_type == "context":
            tracker.annotate(line.content)

    return lines


class FunctionContextTracker:
    def __init__(
        self,
        filename: str | None = None,
        *,
        scriptlet_files: Collection[str] | None = None,
    ) -> None:
        self.filename = filename
        self.scriptlet_files = set(scriptlet_files or ())
        self.function_name: str | None = None
        self.brace_depth = 0

    def update_filename(self, filename: str | None) -> None:
        self.filename = filename
        self.function_name = None
        self.brace_depth = 0

    def annotate(self, content: str) -> tuple[str | None, str | None]:
        if is_full_line_comment(content):
            return self.function_name, self._execution_context(self.function_name)

        function_match = None
        if self.function_name is None:
            function_match = FUNCTION_START_RE.match(content)
            if function_match:
                self.function_name = function_match.group(1)
                self.brace_depth = _brace_delta(content)

        function_name = self.function_name

        if self.function_name is not None:
            if function_match is None:
                self.brace_depth += _brace_delta(content)
            if self.brace_depth <= 0:
                self.function_name = None
                self.brace_depth = 0

        return function_name, self._execution_context(function_name)

    def _execution_context(self, function_name: str | None) -> str | None:
        if _is_hook_filename(self.filename):
            return "hook"
        if function_name in SCRIPTLET_FUNCTIONS or _is_scriptlet_filename(self.filename, self.scriptlet_files):
            return "scriptlet"
        if function_name in BUILD_FUNCTIONS:
            return "build"
        return None


def _brace_delta(content: str) -> int:
    return content.count("{") - content.count("}")


def _is_hook_filename(filename: str | None) -> bool:
    return bool(filename and filename.endswith(".hook"))


def _is_scriptlet_filename(filename: str | None, scriptlet_files: Collection[str]) -> bool:
    if not filename:
        return False
    return filename.endswith(".install") or filename in scriptlet_files or filename.rsplit("/", maxsplit=1)[-1] in scriptlet_files
