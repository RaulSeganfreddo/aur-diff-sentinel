from __future__ import annotations

from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.pkgbuild_diff_parser import DiffArray, DiffValue


def array_finding(
    *,
    rule_id: str,
    severity: Severity,
    message: str,
    hint: str,
    array: DiffArray,
    old_value: str | None,
    new_value: str | None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        line_number=array.line_number,
        line_content=array.line_content,
        hint=hint,
        filename=array.filename,
        source_type="diff",
        target_line_number=array.line_number,
        change_type="added" if array.sign == "+" else "removed",
        old_value=old_value,
        new_value=new_value,
    )


def value_finding(
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
