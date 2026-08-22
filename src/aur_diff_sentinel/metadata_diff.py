from __future__ import annotations

from pathlib import Path

from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.unified_diff import iter_diff_files, iter_diff_lines


ELF_MAGIC = b"\x7fELF"
SHELL_SHEBANGS = ("#!/bin/sh", "#!/usr/bin/sh", "#!/bin/bash", "#!/usr/bin/bash")
ADDED_FILE_RULES = {
    ".install": "install-script-added",
    ".hook": "pacman-hook-added",
}
METADATA_FINDINGS = {
    "install-script-added": (
        Severity.MEDIUM,
        "Install script file added",
        "Install scripts can run on the live system during install, upgrade, or removal.",
    ),
    "pacman-hook-added": (
        Severity.MEDIUM,
        "Pacman hook file added",
        "Pacman hooks can run automatically during package transactions.",
    ),
    "aur-metadata-executable-added": (
        Severity.MEDIUM,
        "Executable script file added",
        "New executable scripts in AUR metadata should be reviewed before updating.",
    ),
    "aur-metadata-elf-added": (
        Severity.HIGH,
        "ELF file added directly to AUR metadata",
        "Compiled binaries committed directly to AUR metadata should be reviewed carefully.",
    ),
}


def analyze_metadata_tree_changes(old_dir: Path, new_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not new_dir.exists():
        return findings

    for path in sorted(new_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(new_dir)
        if ".git" in relative.parts or (old_dir / relative).exists():
            continue
        try:
            with path.open("rb") as file:
                if file.read(len(ELF_MAGIC)) != ELF_MAGIC:
                    continue
        except OSError:
            continue
        findings.append(
            metadata_file_finding(
                "aur-metadata-elf-added",
                relative.as_posix(),
                line_content="<ELF binary>",
            )
        )
    return findings


def find_added_metadata_files(text: str) -> list[Finding]:
    findings: list[Finding] = []
    shell_files_reported: set[str] = set()

    for event in iter_diff_files(text):
        filename = event.new_filename
        if not event.is_new_file or filename is None:
            continue
        rule_id = next((rule for suffix, rule in ADDED_FILE_RULES.items() if filename.endswith(suffix)), None)
        if rule_id:
            findings.append(metadata_file_finding(rule_id, filename))

    for line in iter_diff_lines(text):
        filename = line.file.new_filename
        if not line.file.is_new_file or filename is None or line.change_type != "added":
            continue
        rule_id = None
        if filename not in shell_files_reported and line.content.startswith(SHELL_SHEBANGS):
            rule_id = "aur-metadata-executable-added"
            shell_files_reported.add(filename)
        elif line.content.startswith(ELF_MAGIC.decode()):
            rule_id = "aur-metadata-elf-added"
        if rule_id:
            findings.append(metadata_file_finding(rule_id, filename, line_content=line.content))
    return findings


def metadata_file_finding(
    rule_id: str,
    filename: str,
    *,
    line_content: str | None = None,
) -> Finding:
    severity, message, hint = METADATA_FINDINGS[rule_id]
    return Finding(
        rule_id,
        severity,
        message,
        1,
        line_content or filename,
        hint,
        filename,
        source_type="diff",
        target_line_number=1,
        change_type="added",
        new_value=filename,
    )
