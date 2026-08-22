from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace
from pathlib import PurePosixPath

from aur_diff_sentinel.command_analysis import (
    is_cd_to_non_temp_dir,
    is_cd_to_temp_dir,
    is_js_package_manager_command,
)
from aur_diff_sentinel.models import Finding, Severity, SourceLine
from aur_diff_sentinel.shell_analysis import shell_commands
from aur_diff_sentinel.source_lines import is_full_line_comment


def sequence_findings(lines: list[SourceLine]) -> list[Finding]:
    findings: list[Finding] = []
    working_directory_by_block: dict[tuple[str | None, str | None, str | None, int | None], str] = {}
    seen_temp_package_install: set[tuple[str | None, str | None, str | None, int | None]] = set()

    for line in lines:
        if is_full_line_comment(line.content):
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
                    Finding.from_source(
                        line,
                        rule_id="temporary-directory-package-install",
                        severity=Severity.HIGH,
                        message="Package manager runs from a temporary directory",
                        hint=(
                            "Installing packages from /tmp or /var/tmp in an install script "
                            "or pacman hook runs on the live system and needs review."
                        ),
                    )
                )
                seen_temp_package_install.add(block_key)

    return findings


def with_composite_findings(
    findings: list[Finding],
    *,
    filenames: Iterable[str | None] = (),
) -> list[Finding]:
    units = review_units((*filenames, *(finding.filename for finding in findings)))
    added: list[Finding] = []
    for unit in dict.fromkeys(units[finding.filename] for finding in findings):
        scoped = [finding for finding in findings if units[finding.filename] == unit]
        enriched = _add_dependency_risk_composite(
            _add_suspicious_live_install_sequence(scoped)
        )
        added.extend(enriched[len(scoped):])
    return [*findings, *added]


def review_units(filenames: Iterable[str | None]) -> dict[str | None, str | None]:
    unique_filenames = tuple(dict.fromkeys(filenames))
    anchors = sorted(
        {
            PurePosixPath(filename).parent
            for filename in unique_filenames
            if filename is not None
            and PurePosixPath(filename).name in {"PKGBUILD", ".SRCINFO"}
        },
        key=lambda path: len(path.parts),
        reverse=True,
    )
    units: dict[str | None, str | None] = {}
    for filename in unique_filenames:
        if filename is None:
            units[filename] = None
            continue
        path = PurePosixPath(filename)
        unit = next(
            (anchor for anchor in anchors if path == anchor or anchor in path.parents),
            path.parent,
        )
        units[filename] = unit.as_posix()
    return units


def _add_suspicious_live_install_sequence(findings: list[Finding]) -> list[Finding]:
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
        replace(
            anchor,
            rule_id="suspicious-live-install-sequence",
            severity=Severity.HIGH,
            message="Combined live-system package install sequence",
            hint=(
                "A new JavaScript tooling dependency, install script or hook, "
                "temporary directory, and package-manager command appeared together."
            ),
            old_value=None,
            new_value=None,
        ),
    ]


DEPENDENCY_ADDED_IDS = frozenset({
    "javascript-tooling-dependency-added",
    "build-tool-dependency-added",
    "aur-dependency-added",
    "dependency-added",
})

DEPENDENCY_RISK_SIGNALS = frozenset({
    "install-script-added",
    "pacman-hook-added",
    "source-domain-changed",
    "checksum-skip-added",
    "checksum-array-removed",
    "checksum-algorithm-weakened",
    "network-in-build",
    "direct-exec-package-manager",
    "decoded-pipe-shell",
    "curl-pipe-shell",
    "eval-used",
    "setuid-permission",
    "privilege-command",
    "scriptlet-package-manager",
    "temporary-directory-package-install",
})


def _add_dependency_risk_composite(findings: list[Finding]) -> list[Finding]:
    ids = {finding.rule_id for finding in findings}
    has_dep = bool(ids & DEPENDENCY_ADDED_IDS)
    has_risk = bool(ids & DEPENDENCY_RISK_SIGNALS)
    if not (has_dep and has_risk):
        return findings
    if "dependency-with-risk-signals" in ids:
        return findings

    anchor = next(
        finding
        for finding in findings
        if finding.rule_id in DEPENDENCY_RISK_SIGNALS
    )
    return [
        *findings,
        replace(
            anchor,
            rule_id="dependency-with-risk-signals",
            severity=Severity.HIGH,
            message="New dependency combined with high-risk signals",
            hint=(
                "New dependencies appeared together with other high-risk signals. "
                "Combined review is strongly recommended."
            ),
            old_value=None,
            new_value=None,
        ),
    ]


def _sequence_block_key(line: SourceLine) -> tuple[str | None, str | None, str | None, int | None]:
    if line.execution_context == "hook" and _is_hook_exec(line.content):
        return (line.filename, line.function_name, line.execution_context, line.line_number)
    return (line.filename, line.function_name, line.execution_context, None)


def _is_hook_exec(content: str) -> bool:
    return re.match(r"^\s*Exec\s*=", content, re.IGNORECASE) is not None
