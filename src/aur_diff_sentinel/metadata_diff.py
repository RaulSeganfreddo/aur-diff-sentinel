from __future__ import annotations

from pathlib import Path

from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.pkgbuild_diff_parser import filename_from_diff_header


ELF_MAGIC = b"\x7fELF"


def analyze_metadata_tree_changes(old_dir: Path, new_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not new_dir.exists():
        return findings

    for path in sorted(new_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative_path = path.relative_to(new_dir)
        if ".git" in relative_path.parts:
            continue
        if (old_dir / relative_path).exists():
            continue
        try:
            with path.open("rb") as file:
                magic = file.read(len(ELF_MAGIC))
        except OSError:
            continue
        if magic != ELF_MAGIC:
            continue
        filename = relative_path.as_posix()
        findings.append(
            metadata_file_finding(
                "aur-metadata-elf-added",
                Severity.HIGH,
                "ELF file added directly to AUR metadata",
                "Compiled binaries committed directly to AUR metadata should be reviewed carefully.",
                filename,
                line_content="<ELF binary>",
            )
        )

    return findings


def find_added_metadata_files(text: str) -> list[Finding]:
    findings: list[Finding] = []
    current_old: str | None = None
    current_new: str | None = None
    current_new_file = False
    shell_file_reported = False

    for raw_line in text.splitlines():
        if raw_line.startswith("diff --git "):
            current_old = None
            current_new = None
            current_new_file = False
            shell_file_reported = False
            continue
        if raw_line.startswith("---"):
            current_old = filename_from_diff_header(raw_line)
            continue
        if raw_line.startswith("+++"):
            current_new = filename_from_diff_header(raw_line)
            current_new_file = current_old is None and current_new is not None
            if current_new_file and current_new is not None:
                if current_new.endswith(".install"):
                    findings.append(
                        metadata_file_finding(
                            "install-script-added",
                            Severity.MEDIUM,
                            "Install script file added",
                            "Install scripts can run on the live system during install, upgrade, or removal.",
                            current_new,
                        )
                    )
                elif current_new.endswith(".hook"):
                    findings.append(
                        metadata_file_finding(
                            "pacman-hook-added",
                            Severity.MEDIUM,
                            "Pacman hook file added",
                            "Pacman hooks can run automatically during package transactions.",
                            current_new,
                        )
                    )
            continue
        if not current_new_file or current_new is None or not raw_line.startswith("+"):
            continue
        content = raw_line[1:]
        if not shell_file_reported and (
            content.startswith("#!/bin/sh")
            or content.startswith("#!/usr/bin/sh")
            or content.startswith("#!/bin/bash")
            or content.startswith("#!/usr/bin/bash")
        ):
            findings.append(
                metadata_file_finding(
                    "aur-metadata-executable-added",
                    Severity.MEDIUM,
                    "Executable script file added",
                    "New executable scripts in AUR metadata should be reviewed before updating.",
                    current_new,
                    line_content=content,
                )
            )
            shell_file_reported = True
        if content.startswith("\x7fELF"):
            findings.append(
                metadata_file_finding(
                    "aur-metadata-elf-added",
                    Severity.HIGH,
                    "ELF file added directly to AUR metadata",
                    "Compiled binaries committed directly to AUR metadata should be reviewed carefully.",
                    current_new,
                    line_content=content,
                )
            )

    return findings


def metadata_file_finding(
    rule_id: str,
    severity: Severity,
    message: str,
    hint: str,
    filename: str,
    *,
    line_content: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        line_number=1,
        line_content=line_content or filename,
        hint=hint,
        filename=filename,
        source_type="diff",
        target_line_number=1,
        change_type="added",
        new_value=filename,
    )
