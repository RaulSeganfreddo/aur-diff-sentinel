from __future__ import annotations

import re
from collections.abc import Callable

from aur_diff_sentinel.diff_findings import value_finding
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.pkgbuild_diff_parser import (
    HUNK_HEADER_RE,
    DiffArrays,
    DiffValue,
    dependency_group,
    dependency_group_for,
    dependency_name,
    filename_from_diff_header,
    is_dependency,
    dependency_values_by_name,
)


JS_TOOLING_DEPENDENCIES = {"bun", "npm", "nodejs", "yarn", "pnpm"}

BUILD_TOOL_DEPENDENCIES = {
    "cargo", "rustup",
    "python-pip", "python-pipx", "pip", "pipx",
    "go",
    "ruby", "rubygems", "gem", "bundler",
    "dotnet-sdk", "dotnet-runtime",
    "luarocks",
    "opam",
    "stack", "cabal-install",
    "composer",
    "raku", "zef",
}

_AUR_NAME_PATTERN = re.compile(
    r"-(?:git|bin|svn|hg|bzr|nightly|insider|alpha|beta|rc\d*|dev|patched|appindicator)$"
)

DEPENDENCY_ADDED_RULE_IDS = frozenset({
    "javascript-tooling-dependency-added",
    "build-tool-dependency-added",
    "aur-dependency-added",
    "dependency-added",
})


def _aur_name_heuristic(name: str) -> bool:
    return bool(_AUR_NAME_PATTERN.search(name))


def _classify_new_dependency(
    name: str,
    *,
    is_aur_package: Callable[[str], bool] | None = None,
) -> tuple[str, Severity]:
    if name in JS_TOOLING_DEPENDENCIES:
        return "javascript-tooling-dependency-added", Severity.MEDIUM
    if name in BUILD_TOOL_DEPENDENCIES:
        return "build-tool-dependency-added", Severity.MEDIUM
    if _aur_name_heuristic(name) or (is_aur_package is not None and is_aur_package(name)):
        return "aur-dependency-added", Severity.MEDIUM
    return "dependency-added", Severity.LOW


def find_dependency_changes(
    arrays: DiffArrays,
    *,
    is_aur_package: Callable[[str], bool] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    old_dependencies = dependency_values_by_name(arrays.old_state)
    new_dependencies = dependency_values_by_name(arrays.new_state)
    old_all = {dependency_name(value.value) for values in old_dependencies.values() for value in values}
    new_all = {dependency_name(value.value) for values in new_dependencies.values() for value in values}

    for value in arrays.added_values:
        if not is_dependency(value):
            continue
        name = dependency_name(value.value)
        if name in old_all:
            if dependency_group_for(name, old_dependencies) != dependency_group(value.name):
                findings.append(
                    value_finding(
                        rule_id="dependency-moved",
                        severity=Severity.LOW,
                        message=f"Dependency moved to {value.name}",
                        hint="Dependency group changes should be checked for packaging intent.",
                        value=value,
                        old_value=dependency_group_for(name, old_dependencies),
                        new_value=dependency_group(value.name),
                    )
                )
            continue
        rule_id, severity = _classify_new_dependency(name, is_aur_package=is_aur_package)
        group = dependency_group(value.name)
        findings.append(
            value_finding(
                rule_id=rule_id,
                severity=severity,
                message=_dependency_added_message(rule_id, group, name),
                hint=_dependency_added_hint(rule_id),
                value=value,
                old_value=None,
                new_value=name,
            )
        )

    for value in arrays.removed_values:
        if not is_dependency(value):
            continue
        name = dependency_name(value.value)
        if name in new_all:
            continue
        findings.append(
            value_finding(
                rule_id="dependency-removed",
                severity=Severity.LOW,
                message=f"Dependency removed: {name}",
                hint="Removed dependencies may be normal packaging churn, but can change review context.",
                value=value,
                old_value=name,
                new_value=None,
            )
        )

    return findings


def find_srcinfo_dependency_changes(
    text: str,
    *,
    is_aur_package: Callable[[str], bool] | None = None,
) -> list[Finding]:
    added: list[DiffValue] = []
    removed_names: set[str] = set()
    current_filename: str | None = None
    old_line_number: int | None = None
    new_line_number: int | None = None

    for raw_line in text.splitlines():
        if raw_line.startswith("diff --git "):
            current_filename = None
            old_line_number = None
            new_line_number = None
            continue
        if raw_line.startswith("+++"):
            current_filename = filename_from_diff_header(raw_line)
            continue
        hunk_match = HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            old_line_number = int(hunk_match.group(1))
            new_line_number = int(hunk_match.group(2))
            continue
        if old_line_number is None or new_line_number is None:
            continue
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            value = srcinfo_dependency_value(raw_line[1:], current_filename)
            if value is not None:
                removed_names.add(dependency_name(value.value))
            old_line_number += 1
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            value = srcinfo_dependency_value(raw_line[1:], current_filename, new_line_number)
            if value is not None:
                added.append(value)
            new_line_number += 1
            continue
        old_line_number += 1
        new_line_number += 1

    findings: list[Finding] = []
    for value in added:
        name = dependency_name(value.value)
        if name in removed_names:
            continue
        rule_id, severity = _classify_new_dependency(name, is_aur_package=is_aur_package)
        group = dependency_group(value.name)
        findings.append(
            value_finding(
                rule_id=rule_id,
                severity=severity,
                message=_dependency_added_message(rule_id, group, name),
                hint=_dependency_added_hint(rule_id),
                value=value,
                old_value=None,
                new_value=name,
            )
        )
    return findings


def srcinfo_dependency_value(
    content: str,
    filename: str | None,
    line_number: int = 0,
) -> DiffValue | None:
    if filename != ".SRCINFO" and not (filename and filename.endswith("/.SRCINFO")):
        return None
    match = re.match(
        r"^\s*(depends(?:_[a-z0-9_]+)?|makedepends(?:_[a-z0-9_]+)?|checkdepends(?:_[a-z0-9_]+)?|optdepends(?:_[a-z0-9_]+)?)\s*=\s*(\S+)",
        content,
    )
    if not match:
        return None
    return DiffValue(
        name=match.group(1),
        value=match.group(2),
        index=0,
        line_number=line_number,
        line_content=content,
        filename=filename,
    )


def dedupe_srcinfo_dependency_findings(
    existing: list[Finding],
    srcinfo_findings: list[Finding],
) -> list[Finding]:
    pkgbuild_dependency_values = {
        finding.new_value
        for finding in existing
        if finding.rule_id in DEPENDENCY_ADDED_RULE_IDS
        and (finding.filename == "PKGBUILD" or bool(finding.filename and finding.filename.endswith("/PKGBUILD")))
    }
    return [
        finding
        for finding in srcinfo_findings
        if finding.new_value not in pkgbuild_dependency_values
    ]


def _dependency_added_message(rule_id: str, group: str, name: str) -> str:
    if rule_id == "javascript-tooling-dependency-added":
        return f"JavaScript tooling dependency added to {group}: {name}"
    if rule_id == "build-tool-dependency-added":
        return f"Build-tool dependency added to {group}: {name}"
    if rule_id == "aur-dependency-added":
        return f"AUR dependency added to {group}: {name}"
    return f"Dependency added to {group}: {name}"


def _dependency_added_hint(rule_id: str) -> str:
    if rule_id == "javascript-tooling-dependency-added":
        return "New JavaScript tooling dependencies can be legitimate, but should be reviewed with install scripts and hooks."
    if rule_id == "build-tool-dependency-added":
        return "New build-tool dependencies can fetch or execute external code and should be reviewed."
    if rule_id == "aur-dependency-added":
        return "New AUR dependencies expand the package's trust boundary and should be reviewed."
    return "New dependencies should be reviewed for packaging intent."
