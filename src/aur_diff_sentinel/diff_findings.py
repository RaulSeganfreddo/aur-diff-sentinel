from __future__ import annotations

from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.pkgbuild_diff_parser import DiffArray, DiffValue


def diff_finding(
    *,
    rule_id: str,
    severity: Severity,
    message: str,
    hint: str,
    location: DiffArray | DiffValue,
    old_value: str | None,
    new_value: str | None,
) -> Finding:
    if location.sign not in {"+", "-"}:
        raise ValueError("diff finding location must identify an added or removed value")
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        line_number=location.line_number,
        line_content=location.line_content,
        hint=hint,
        filename=location.filename,
        source_type="diff",
        target_line_number=location.line_number,
        change_type="added" if location.sign == "+" else "removed",
        old_value=old_value,
        new_value=new_value,
    )
