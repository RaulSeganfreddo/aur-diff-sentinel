from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from aur_diff_sentinel.diff_analysis import analyze_source_diff
from aur_diff_sentinel.models import Finding, Rule, Severity, SourceLine
from aur_diff_sentinel.pkgbuild_analysis import analyze_pkgbuild_checksums
from aur_diff_sentinel.rules import RULES
from aur_diff_sentinel.rules import changes_to_temp_dir as _changes_to_temp_dir
from aur_diff_sentinel.rules import uses_js_package_manager as _uses_js_package_manager


HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
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


def _is_full_line_comment(content: str) -> bool:
    return content.lstrip().startswith("#")


def _brace_delta(content: str) -> int:
    return content.count("{") - content.count("}")


class FunctionContextTracker:
    def __init__(self, filename: str | None = None) -> None:
        self.filename = filename
        self.function_name: str | None = None
        self.brace_depth = 0

    def update_filename(self, filename: str | None) -> None:
        self.filename = filename
        self.function_name = None
        self.brace_depth = 0

    def annotate(self, content: str) -> tuple[str | None, str | None]:
        if _is_full_line_comment(content):
            return self.function_name, self._execution_context(self.function_name)

        function_match = None
        if self.function_name is None:
            function_match = FUNCTION_START_RE.match(content)
            if function_match:
                self.function_name = function_match.group(1)
                self.brace_depth = max(1, _brace_delta(content))

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
        if function_name in SCRIPTLET_FUNCTIONS:
            return "scriptlet"
        if function_name in BUILD_FUNCTIONS:
            return "build"
        return None


def source_lines_from_text(text: str, filename: str | None = None) -> list[SourceLine]:
    tracker = FunctionContextTracker(filename)
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


def source_lines_from_diff(text: str, filename: str | None = None) -> list[SourceLine]:
    lines: list[SourceLine] = []
    current_filename = filename
    target_line_number: int | None = None
    tracker = FunctionContextTracker(filename)

    for index, line in enumerate(text.splitlines(), start=1):
        if line.startswith("diff --git "):
            current_filename = filename
            target_line_number = None
            tracker = FunctionContextTracker(filename)
            continue

        if line.startswith("+++"):
            current_filename = _filename_from_diff_header(line) or filename
            tracker.update_filename(current_filename)
            continue

        hunk_match = HUNK_HEADER_RE.match(line)
        if hunk_match:
            target_line_number = int(hunk_match.group(1))
            tracker = FunctionContextTracker(current_filename)
            continue

        if target_line_number is None:
            continue

        if line.startswith("+"):
            content = line[1:]
            function_name, execution_context = tracker.annotate(content)
            lines.append(
                SourceLine(
                    line_number=target_line_number,
                    content=content,
                    filename=current_filename,
                    source_type="diff",
                    diff_line_number=index,
                    target_line_number=target_line_number,
                    change_type="added",
                    function_name=function_name,
                    execution_context=execution_context,
                )
            )
            target_line_number += 1
            continue

        if line.startswith("-"):
            continue

        if line.startswith("\\"):
            continue

        context_content = line[1:] if line.startswith(" ") else line
        tracker.annotate(context_content)
        target_line_number += 1

    return lines


def scan_lines(
    lines: Iterable[SourceLine],
    rules: Sequence[Rule] = RULES,
) -> list[Finding]:
    findings: list[Finding] = []

    for line in lines:
        if _is_full_line_comment(line.content):
            continue
        for rule in rules:
            if rule.matches(line):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        message=rule.message,
                        line_number=line.line_number,
                        line_content=line.content,
                        hint=rule.hint,
                        filename=line.filename,
                        source_type=line.source_type,
                        diff_line_number=line.diff_line_number,
                        target_line_number=line.target_line_number,
                        change_type=line.change_type,
                        function_name=line.function_name,
                        execution_context=line.execution_context,
                    )
                )

    return findings


def scan_text(
    text: str,
    rules: Sequence[Rule] = RULES,
    filename: str | None = None,
) -> list[Finding]:
    lines = source_lines_from_text(text, filename=filename)
    findings = scan_lines(lines, rules=rules)
    if rules is RULES:
        findings.extend(_sequence_findings(lines))
        findings.extend(analyze_pkgbuild_checksums(text, filename=filename))
        findings = _with_composite_findings(findings)
    return _sort_findings_by_source_order(findings)


def _sort_findings_by_source_order(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(
        enumerate(findings),
        key=lambda item: (item[1].line_number, item[0]),
    )
    return [finding for _index, finding in ordered]


def scan_diff_text(
    text: str,
    rules: Sequence[Rule] = RULES,
    filename: str | None = None,
) -> list[Finding]:
    lines = source_lines_from_diff(text, filename=filename)
    line_findings = scan_lines(lines, rules=rules)
    if rules is RULES:
        line_findings.extend(_sequence_findings(lines))
    diff_findings = analyze_source_diff(text)
    contextual_skip_locations = {
        (finding.filename, finding.line_number)
        for finding in diff_findings
        if finding.rule_id == "checksum-skip-added"
    }
    filtered_line_findings = [
        finding
        for finding in line_findings
        if not (
            finding.rule_id == "checksum-skip"
            and (finding.filename, finding.line_number) in contextual_skip_locations
        )
    ]
    findings = [*filtered_line_findings, *diff_findings]
    if rules is RULES:
        findings = _with_composite_findings(findings)
    return findings


def _is_hook_filename(filename: str | None) -> bool:
    return bool(filename and filename.endswith(".hook"))


def _sequence_findings(lines: list[SourceLine]) -> list[Finding]:
    findings: list[Finding] = []
    temp_dir_by_block: dict[tuple[str | None, str | None, str | None], SourceLine] = {}
    seen_temp_package_install: set[tuple[str | None, str | None, str | None]] = set()

    for line in lines:
        if _is_full_line_comment(line.content):
            continue
        block_key = (line.filename, line.function_name, line.execution_context)
        if line.execution_context in {"scriptlet", "hook"} and _changes_to_temp_dir(line.content):
            temp_dir_by_block[block_key] = line
        if (
            line.execution_context in {"scriptlet", "hook"}
            and _uses_js_package_manager(line.content)
            and (block_key in temp_dir_by_block or _changes_to_temp_dir(line.content))
            and block_key not in seen_temp_package_install
        ):
            findings.append(
                Finding(
                    rule_id="temporary-directory-package-install",
                    severity=Severity.HIGH,
                    message="Package manager runs from a temporary directory",
                    line_number=line.line_number,
                    line_content=line.content,
                    hint=(
                        "Installing packages from /tmp or /var/tmp in an install script "
                        "or pacman hook runs on the live system and needs review."
                    ),
                    filename=line.filename,
                    source_type=line.source_type,
                    diff_line_number=line.diff_line_number,
                    target_line_number=line.target_line_number,
                    change_type=line.change_type,
                    function_name=line.function_name,
                    execution_context=line.execution_context,
                )
            )
            seen_temp_package_install.add(block_key)

    return findings


def _with_composite_findings(findings: list[Finding]) -> list[Finding]:
    ids = {finding.rule_id for finding in findings}
    has_script_entry = bool(
        ids
        & {
            "install-script",
            "install-script-added",
            "pacman-hook-added",
            "pacman-hook-exec",
        }
    )
    if not (
        "suspicious-runtime-dependency-added" in ids
        and has_script_entry
        and "scriptlet-package-manager" in ids
        and "temporary-directory-package-install" in ids
    ):
        return findings
    if "suspicious-live-install-sequence" in ids:
        return findings

    anchor = next(
        finding
        for finding in findings
        if finding.rule_id in {"temporary-directory-package-install", "scriptlet-package-manager"}
    )
    return [
        *findings,
        Finding(
            rule_id="suspicious-live-install-sequence",
            severity=Severity.HIGH,
            message="Combined live-system package install sequence",
            line_number=anchor.line_number,
            line_content=anchor.line_content,
            hint=(
                "A new JavaScript tooling dependency, install script or hook, "
                "temporary directory, and package-manager command appeared together."
            ),
            filename=anchor.filename,
            source_type=anchor.source_type,
            diff_line_number=anchor.diff_line_number,
            target_line_number=anchor.target_line_number,
            change_type=anchor.change_type,
            function_name=anchor.function_name,
            execution_context=anchor.execution_context,
        ),
    ]
