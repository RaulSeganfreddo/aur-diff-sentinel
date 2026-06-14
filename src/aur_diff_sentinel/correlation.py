from __future__ import annotations

import re

from aur_diff_sentinel.command_analysis import (
    is_cd_to_non_temp_dir,
    is_cd_to_temp_dir,
    is_js_package_manager_command,
)
from aur_diff_sentinel.models import Finding, Severity, SourceLine
from aur_diff_sentinel.shell_analysis import shell_commands


def sequence_findings(lines: list[SourceLine]) -> list[Finding]:
    findings: list[Finding] = []
    working_directory_by_block: dict[tuple[str | None, str | None, str | None, int | None], str] = {}
    seen_temp_package_install: set[tuple[str | None, str | None, str | None, int | None]] = set()

    for line in lines:
        if _is_full_line_comment(line.content):
            continue
        block_key = _sequence_block_key(line)
        if line.execution_context not in {"scriptlet", "hook"}:
            continue
        for command in shell_commands(line.content):
            if is_cd_to_temp_dir(command):
                working_directory_by_block[block_key] = "temporary"
                continue
            if is_cd_to_non_temp_dir(command):
                working_directory_by_block[block_key] = "non-temporary"
                continue
            if (
                is_js_package_manager_command(command)
                and working_directory_by_block.get(block_key) == "temporary"
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


def with_composite_findings(findings: list[Finding]) -> list[Finding]:
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
        "javascript-tooling-dependency-added" in ids
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


def _sequence_block_key(line: SourceLine) -> tuple[str | None, str | None, str | None, int | None]:
    if line.execution_context == "hook" and _is_hook_exec(line.content):
        return (line.filename, line.function_name, line.execution_context, line.line_number)
    return (line.filename, line.function_name, line.execution_context, None)


def _is_hook_exec(content: str) -> bool:
    return re.match(r"^\s*Exec\s*=", content, re.IGNORECASE) is not None


def _is_full_line_comment(content: str) -> bool:
    return content.lstrip().startswith("#")
