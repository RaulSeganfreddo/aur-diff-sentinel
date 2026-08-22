from __future__ import annotations

import re
from collections.abc import Callable

from aur_diff_sentinel.correlation import review_units
from aur_diff_sentinel.diff_findings import diff_finding
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.pkgbuild_diff_parser import (
    DiffArrays,
    dependency_group_for,
    dependency_values_by_name,
)
from aur_diff_sentinel.pkgbuild_syntax import ArrayValue, dependency_group, dependency_name, is_dependency_name
from aur_diff_sentinel.provider import looks_like_aur_package_name
from aur_diff_sentinel.unified_diff import iter_diff_lines


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

DEPENDENCY_ADDED_RULE_IDS = frozenset({
    "javascript-tooling-dependency-added",
    "build-tool-dependency-added",
    "aur-dependency-added",
    "dependency-added",
})

DEPENDENCY_DETAILS = {
    "javascript-tooling-dependency-added": (
        "JavaScript tooling",
        "New JavaScript tooling dependencies can be legitimate, but should be reviewed with install scripts and hooks.",
    ),
    "build-tool-dependency-added": (
        "Build-tool",
        "New build-tool dependencies can fetch or execute external code and should be reviewed.",
    ),
    "aur-dependency-added": (
        "AUR",
        "New AUR dependencies expand the package's trust boundary and should be reviewed.",
    ),
    "dependency-added": ("", "New dependencies should be reviewed for packaging intent."),
}


def _classify_new_dependency(
    name: str,
    *,
    is_aur_package: Callable[[str], bool] | None = None,
) -> tuple[str, Severity]:
    if name in JS_TOOLING_DEPENDENCIES:
        return "javascript-tooling-dependency-added", Severity.MEDIUM
    if name in BUILD_TOOL_DEPENDENCIES:
        return "build-tool-dependency-added", Severity.MEDIUM
    if looks_like_aur_package_name(name) or (is_aur_package is not None and is_aur_package(name)):
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
        if not is_dependency_name(value.name) or not value.value:
            continue
        name = dependency_name(value.value)
        if name in old_all:
            old_group = dependency_group_for(name, old_dependencies)
            new_group = dependency_group(value.name)
            if old_group != new_group:
                findings.append(
                    diff_finding(
                        rule_id="dependency-moved",
                        severity=Severity.LOW,
                        message=f"Dependency moved to {value.name}",
                        hint="Dependency group changes should be checked for packaging intent.",
                        location=value,
                        old_value=old_group,
                        new_value=new_group,
                    )
                )
            continue
        findings.append(_new_dependency_finding(value, is_aur_package))

    for value in arrays.removed_values:
        if not is_dependency_name(value.name) or not value.value:
            continue
        name = dependency_name(value.value)
        if name in new_all:
            continue
        findings.append(
            diff_finding(
                rule_id="dependency-removed",
                severity=Severity.LOW,
                message=f"Dependency removed: {name}",
                hint="Removed dependencies may be normal packaging churn, but can change review context.",
                location=value,
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
    added: list[ArrayValue] = []
    removed_names: dict[str | None, set[str]] = {}

    for line in iter_diff_lines(text):
        if line.change_type not in {"removed", "added"}:
            continue
        value = srcinfo_dependency_value(
            line.content,
            line.filename,
            line.line_number,
            sign="-" if line.change_type == "removed" else "+",
        )
        if value is None:
            continue
        if line.change_type == "removed":
            removed_names.setdefault(value.filename, set()).add(dependency_name(value.value))
        else:
            added.append(value)

    findings: list[Finding] = []
    for value in added:
        name = dependency_name(value.value)
        if name in removed_names.get(value.filename, set()):
            continue
        findings.append(_new_dependency_finding(value, is_aur_package))
    return findings


def srcinfo_dependency_value(
    content: str,
    filename: str | None,
    line_number: int = 0,
    *,
    sign: str = "",
) -> ArrayValue | None:
    if filename != ".SRCINFO" and not (filename and filename.endswith("/.SRCINFO")):
        return None
    match = re.match(
        r"^\s*(depends(?:_[a-z0-9_]+)?|makedepends(?:_[a-z0-9_]+)?|checkdepends(?:_[a-z0-9_]+)?|optdepends(?:_[a-z0-9_]+)?)\s*=\s*(\S+)",
        content,
    )
    if not match:
        return None
    return ArrayValue(
        name=match.group(1),
        value=match.group(2),
        index=0,
        line_number=line_number,
        line_content=content,
        filename=filename,
        sign=sign,
    )


def dedupe_srcinfo_dependency_findings(
    existing: list[Finding],
    srcinfo_findings: list[Finding],
) -> list[Finding]:
    units = review_units(
        finding.filename for finding in [*existing, *srcinfo_findings]
    )
    pkgbuild_dependency_values = {
        (units[finding.filename], finding.new_value)
        for finding in existing
        if finding.rule_id in DEPENDENCY_ADDED_RULE_IDS
        and (finding.filename == "PKGBUILD" or bool(finding.filename and finding.filename.endswith("/PKGBUILD")))
    }
    return [
        finding
        for finding in srcinfo_findings
        if (units[finding.filename], finding.new_value) not in pkgbuild_dependency_values
    ]


def _new_dependency_finding(
    value: ArrayValue,
    is_aur_package: Callable[[str], bool] | None,
) -> Finding:
    name = dependency_name(value.value)
    rule_id, severity = _classify_new_dependency(name, is_aur_package=is_aur_package)
    label, hint = DEPENDENCY_DETAILS[rule_id]
    subject = f"{label} dependency" if label else "Dependency"
    return diff_finding(
        rule_id=rule_id,
        severity=severity,
        message=f"{subject} added to {dependency_group(value.name)}: {name}",
        hint=hint,
        location=value,
        old_value=None,
        new_value=name,
    )
