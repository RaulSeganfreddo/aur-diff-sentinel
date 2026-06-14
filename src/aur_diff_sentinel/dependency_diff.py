from __future__ import annotations

import re

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


def find_dependency_changes(arrays: DiffArrays) -> list[Finding]:
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
        if name in JS_TOOLING_DEPENDENCIES:
            findings.append(
                value_finding(
                    rule_id="javascript-tooling-dependency-added",
                    severity=Severity.MEDIUM,
                    message=f"JavaScript tooling dependency added to {dependency_group(value.name)}: {name}",
                    hint="New JavaScript tooling dependencies can be legitimate, but should be reviewed with install scripts and hooks.",
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


def find_srcinfo_dependency_changes(text: str) -> list[Finding]:
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
        if name in removed_names or name not in JS_TOOLING_DEPENDENCIES:
            continue
        findings.append(
            value_finding(
                rule_id="javascript-tooling-dependency-added",
                severity=Severity.MEDIUM,
                message=f"JavaScript tooling dependency added to {dependency_group(value.name)}: {name}",
                hint="New JavaScript tooling dependencies can be legitimate, but should be reviewed with install scripts and hooks.",
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
        if finding.rule_id == "javascript-tooling-dependency-added"
        and (finding.filename == "PKGBUILD" or bool(finding.filename and finding.filename.endswith("/PKGBUILD")))
    }
    return [
        finding
        for finding in srcinfo_findings
        if finding.new_value not in pkgbuild_dependency_values
    ]
