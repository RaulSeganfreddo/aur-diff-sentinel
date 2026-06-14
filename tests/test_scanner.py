from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from aur_diff_sentinel.baseline_prune import SelectionError, parse_prune_selection
from aur_diff_sentinel.cache import AurCache, metadata_version, unified_diff_dirs
from aur_diff_sentinel.cli import run
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.provider import (
    AurUpdate,
    InstalledPackageStatus,
    discover_updates,
    parse_update_output,
    query_installed_package,
)
from aur_diff_sentinel.report import format_findings, format_update_review
from aur_diff_sentinel.scanner import scan_diff_text, scan_text, source_lines_from_diff, source_lines_from_text
from aur_diff_sentinel.update_review import (
    PackageReview,
    UpdateReviewResult,
    refresh_cached_reviewed_baselines,
    refresh_reviewed_baselines,
    review_updates,
)

from tests.helpers import (
    SAMPLES,
    copy_repo_fetcher,
    finding as _finding,
    fixture_fetcher,
    rule_ids,
    run_git,
    write_metadata,
)

class ScannerTests(unittest.TestCase):
    def test_eval_is_detected(self) -> None:
        self.assertIn("eval-used", rule_ids('eval "$flags"'))

    def test_curl_pipe_shell_is_detected(self) -> None:
        self.assertIn("curl-pipe-shell", rule_ids("curl https://example.com/install.sh | bash"))
        self.assertIn("curl-pipe-shell", rule_ids("wget -O- https://example.com/install.sh | sh"))

    def test_checksum_skip_is_detected(self) -> None:
        self.assertIn("checksum-skip", rule_ids("sha256sums=('SKIP')"))

    def test_setuid_permission_is_detected(self) -> None:
        self.assertIn("setuid-permission", rule_ids('chmod 4755 "$pkgdir/usr/bin/example"'))
        self.assertIn("setuid-permission", rule_ids('install -Dm4755 helper "$pkgdir/usr/bin/helper"'))

    def test_install_script_is_detected(self) -> None:
        self.assertIn("install-script", rule_ids("install=example.install"))

    def test_shell_c_is_detected(self) -> None:
        self.assertIn("shell-c", rule_ids('bash -c "$generated_command"'))
        self.assertIn("shell-c", rule_ids('sh -c "echo test"'))

    def test_source_command_is_detected(self) -> None:
        self.assertIn("source-command", rule_ids("source ./extra.sh"))
        self.assertIn("source-command", rule_ids('source "$srcdir/extra.sh"'))
        self.assertIn("source-command", rule_ids(". ./extra.sh"))

    def test_source_metadata_is_not_treated_as_shell_source_command(self) -> None:
        self.assertNotIn(
            "source-command",
            {
                finding.rule_id
                for finding in scan_text(
                    "source = file::https://example.invalid/file",
                    filename=".SRCINFO",
                )
            },
        )
        self.assertNotIn("source-command", rule_ids('source=("https://example.invalid/file")'))
        self.assertNotIn("source-command", rule_ids('source_x86_64=("https://example.invalid/file")'))
        self.assertNotIn("source-command", rule_ids('_source="https://example.invalid/file"'))

    def test_decoded_pipe_shell_is_detected_as_high(self) -> None:
        finding = scan_text("base64 -d payload.txt | sh")[0]

        self.assertEqual(finding.rule_id, "decoded-pipe-shell")
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_more_decoded_pipe_shell_forms_are_detected_as_high(self) -> None:
        for command in ("xxd -r payload.hex | bash", "openssl enc -d -in payload | sh"):
            with self.subTest(command=command):
                finding = scan_text(command)[0]

                self.assertEqual(finding.rule_id, "decoded-pipe-shell")
                self.assertEqual(finding.severity, Severity.HIGH)

    def test_standalone_decode_command_is_not_reported_as_high(self) -> None:
        self.assertNotIn("decoded-pipe-shell", rule_ids("xxd -r payload.hex"))

    def test_inline_interpreter_command_is_detected_as_medium(self) -> None:
        for command in ("python -c 'print(1)'", "perl -e 'print 1'", "awk '{ system($0) }'"):
            with self.subTest(command=command):
                finding = scan_text(command)[0]

                self.assertEqual(finding.rule_id, "inline-interpreter-command")
                self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_vcs_checksum_skip_is_medium_in_full_pkgbuild_scan(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    'source=("git+https://example.invalid/project.git")',
                    "sha256sums=('SKIP')",
                ]
            )
        )
        finding = next(finding for finding in findings if finding.rule_id == "checksum-skip")

        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_aliased_vcs_checksum_skip_is_medium_in_full_pkgbuild_scan(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    'source=("project::git+https://example.invalid/project")',
                    "sha256sums=('SKIP')",
                ]
            )
        )
        finding = next(finding for finding in findings if finding.rule_id == "checksum-skip")

        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_non_vcs_checksum_skip_is_high_in_full_pkgbuild_scan(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    'source=("https://example.invalid/project.tar.gz")',
                    "sha256sums=('SKIP')",
                ]
            )
        )
        finding = next(finding for finding in findings if finding.rule_id == "checksum-skip")

        self.assertEqual(finding.severity, Severity.HIGH)

    def test_unknown_source_checksum_skip_stays_high_in_full_pkgbuild_scan(self) -> None:
        findings = scan_text("sha256sums=('SKIP')")
        finding = next(finding for finding in findings if finding.rule_id == "checksum-skip")

        self.assertEqual(finding.severity, Severity.HIGH)

    def test_multiline_vcs_checksum_skip_is_medium_in_full_pkgbuild_scan(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "source=(",
                    '  "git+https://example.invalid/project.git"',
                    ")",
                    "sha256sums=(",
                    "  'SKIP'",
                    ")",
                ]
            )
        )
        finding = next(finding for finding in findings if finding.rule_id == "checksum-skip")

        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.line_number, 5)

    def test_arch_specific_vcs_checksum_skip_is_medium_in_full_pkgbuild_scan(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    'source=("https://example.invalid/common.tar.gz")',
                    "sha256sums=('abc')",
                    'source_x86_64=("git+https://example.invalid/project.git")',
                    "sha256sums_x86_64=('SKIP')",
                ]
            )
        )
        finding = next(finding for finding in findings if finding.rule_id == "checksum-skip")

        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_full_line_comments_are_ignored(self) -> None:
        self.assertEqual(scan_text("# eval \"$flags\"\n# curl https://example.com/file | bash"), [])

    def test_function_context_is_tracked(self) -> None:
        lines = source_lines_from_text(
            "\n".join(
                [
                    "pkgname=example",
                    "prepare() {",
                    "    curl https://example.com/file.tar.gz -o file.tar.gz",
                    "}",
                    "pkgver=1.0",
                    "function package {",
                    "    install -Dm755 example \"$pkgdir/usr/bin/example\"",
                    "}",
                    "pkgrel=1",
                ]
            )
        )

        self.assertEqual(lines[0].function_name, None)
        self.assertEqual(lines[1].function_name, "prepare")
        self.assertEqual(lines[2].function_name, "prepare")
        self.assertEqual(lines[3].function_name, "prepare")
        self.assertEqual(lines[4].function_name, None)
        self.assertEqual(lines[5].function_name, "package")
        self.assertEqual(lines[6].function_name, "package")
        self.assertEqual(lines[8].function_name, None)

    def test_network_in_build_is_detected_inside_build_functions(self) -> None:
        ids = rule_ids(
            "\n".join(
                [
                    "prepare() {",
                    "    curl https://example.com/file.tar.gz -o file.tar.gz",
                    "    git clone https://example.com/repo.git",
                    "    npm install",
                    "}",
                ]
            )
        )

        self.assertIn("network-in-build", ids)

    def test_scriptlet_package_manager_is_detected_with_temp_directory(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "post_install() {{",
                    "    cd /tmp",
                    "    bun add lodash js-digest",
                    "}}",
                ]
            ),
            filename="example.install",
        )
        ids = {finding.rule_id for finding in findings}

        self.assertIn("scriptlet-package-manager", ids)
        self.assertIn("temporary-directory-package-install", ids)
        self.assertEqual(
            next(finding for finding in findings if finding.rule_id == "scriptlet-package-manager").function_name,
            "post_install",
        )

    def test_function_style_scriptlet_is_tracked(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "function post_install {",
                    "    npm install atomic-lockfile",
                    "}",
                ]
            ),
            filename="example.install",
        )
        finding = next(
            finding
            for finding in findings
            if finding.rule_id == "scriptlet-package-manager"
        )

        self.assertEqual(finding.function_name, "post_install")
        self.assertEqual(finding.execution_context, "scriptlet")

    def test_npm_scriptlet_package_manager_is_detected(self) -> None:
        ids = {
            finding.rule_id
            for finding in scan_text(
                "\n".join(
                    [
                        "post_install() {",
                        "    cd /tmp",
                        "    npm install atomic-lockfile yargs",
                        "}",
                    ]
                ),
                filename="example.install",
            )
        }

        self.assertIn("scriptlet-package-manager", ids)
        self.assertIn("temporary-directory-package-install", ids)

    def test_pacman_hook_exec_package_manager_is_detected(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "[Action]",
                    "Exec = /bin/sh -c 'cd /tmp && npm install atomic-lockfile semver dotenv'",
                ]
            ),
            filename="example.hook",
        )
        ids = {finding.rule_id for finding in findings}

        self.assertIn("pacman-hook-exec", ids)
        self.assertIn("scriptlet-package-manager", ids)
        self.assertIn("temporary-directory-package-install", ids)
        self.assertTrue(all(finding.execution_context == "hook" for finding in findings))

    def test_legitimate_install_script_without_package_manager_is_not_high(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "post_install() {",
                    '    echo "Custom flags belong in ~/.config/example-flags.conf"',
                    "}",
                    "",
                    "post_upgrade() {",
                    "    post_install",
                    "}",
                ]
            ),
            filename="example.install",
        )

        self.assertNotIn(
            "scriptlet-package-manager",
            {finding.rule_id for finding in findings},
        )
        self.assertFalse(any(finding.severity == Severity.HIGH for finding in findings))

    def test_comments_and_strings_do_not_match_package_manager_rules(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "# npm install atomic-lockfile",
                    'message="run bun add manually"',
                ]
            ),
            filename="example.install",
        )

        self.assertEqual(findings, [])

    def test_quoted_assignment_inside_scriptlet_does_not_match_package_manager_rules(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "post_install() {",
                    '    message="run bun add manually"',
                    "}",
                ]
            ),
            filename="example.install",
        )

        self.assertNotIn("scriptlet-package-manager", {finding.rule_id for finding in findings})

    def test_install_file_hunk_without_function_signature_still_uses_scriptlet_context(self) -> None:
        text = "\n".join(
            [
                "--- a/example.install",
                "+++ b/example.install",
                "@@ -40,4 +40,5 @@",
                "     existing_command",
                "+    npm install suspicious-package",
                " }",
            ]
        )
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "scriptlet-package-manager"
        )

        self.assertIsNone(finding.function_name)
        self.assertEqual(finding.execution_context, "scriptlet")

    def test_custom_install_reference_hunk_uses_scriptlet_context(self) -> None:
        text = "\n".join(
            [
                "--- a/example-deps",
                "+++ b/example-deps",
                "@@ -1 +1 @@",
                "+npm install suspicious-package",
            ]
        )
        ids = {
            finding.rule_id
            for finding in scan_diff_text(text, scriptlet_files={"example-deps"})
        }

        self.assertIn("scriptlet-package-manager", ids)

    def test_one_line_scriptlet_does_not_leak_function_name_to_following_lines(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    'post_install() { echo "done"; }',
                    "npm install suspicious-package",
                ]
            ),
            filename="example.install",
        )
        package_manager_findings = [
            finding for finding in findings if finding.rule_id == "scriptlet-package-manager"
        ]

        self.assertEqual(len(package_manager_findings), 1)
        self.assertIsNone(package_manager_findings[0].function_name)
        self.assertEqual(package_manager_findings[0].execution_context, "scriptlet")

    def test_hook_shell_payload_package_manager_at_start_is_detected(self) -> None:
        for line in (
            "Exec = /bin/sh -c 'npm install package'",
            'Exec=/usr/bin/bash -c "bun add package"',
        ):
            with self.subTest(line=line):
                ids = {
                    finding.rule_id
                    for finding in scan_text(line, filename="example.hook")
                }

                self.assertIn("pacman-hook-exec", ids)
                self.assertIn("scriptlet-package-manager", ids)

    def test_temp_directory_state_is_cleared_by_later_cd(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "post_install() {",
                    "    cd /tmp",
                    "    prepare_something",
                    "    cd /usr/share/example",
                    "    npm install package",
                    "}",
                ]
            ),
            filename="example.install",
        )
        ids = {finding.rule_id for finding in findings}

        self.assertIn("scriptlet-package-manager", ids)
        self.assertNotIn("temporary-directory-package-install", ids)

    def test_temp_directory_subdirectories_are_treated_as_temporary(self) -> None:
        for command in (
            "cd /tmp/payload\n    npm install package",
            "cd /var/tmp/build-dir\n    bun add package",
        ):
            with self.subTest(command=command):
                findings = scan_text(
                    "\n".join(
                        [
                            "post_install() {",
                            f"    {command}",
                            "}",
                        ]
                    ),
                    filename="example.install",
                )
                ids = {finding.rule_id for finding in findings}

                self.assertIn("scriptlet-package-manager", ids)
                self.assertIn("temporary-directory-package-install", ids)

    def test_same_line_temp_directory_state_follows_command_order(self) -> None:
        for command in (
            "npm install package && cd /tmp",
            "cd /tmp && cd /usr/share/example && npm install package",
        ):
            with self.subTest(command=command):
                findings = scan_text(
                    "\n".join(
                        [
                            "post_install() {",
                            f"    {command}",
                            "}",
                        ]
                    ),
                    filename="example.install",
                )
                ids = {finding.rule_id for finding in findings}

                self.assertIn("scriptlet-package-manager", ids)
                self.assertNotIn("temporary-directory-package-install", ids)

    def test_hook_temp_directory_state_does_not_cross_exec_lines(self) -> None:
        findings = scan_text(
            "\n".join(
                [
                    "[Action]",
                    "Exec = /bin/sh -c 'cd /tmp'",
                    "Exec = /bin/sh -c 'npm install package'",
                ]
            ),
            filename="example.hook",
        )
        ids = {finding.rule_id for finding in findings}

        self.assertIn("scriptlet-package-manager", ids)
        self.assertNotIn("temporary-directory-package-install", ids)

    def test_absolute_env_and_command_package_manager_forms_are_detected(self) -> None:
        ids = {
            finding.rule_id
            for finding in scan_text(
                "\n".join(
                    [
                        "post_install() {",
                        "    cd /tmp && /usr/bin/npm install atomic-lockfile",
                        "    /usr/bin/bun add js-digest",
                        "    env npm install atomic-lockfile",
                        "    command bun add js-digest",
                        "}",
                    ]
                ),
                filename="example.install",
            )
        }

        self.assertIn("scriptlet-package-manager", ids)
        self.assertIn("temporary-directory-package-install", ids)

    def test_env_and_command_options_before_package_manager_are_detected(self) -> None:
        for command in (
            "env HOME=/tmp npm install package",
            "env -i npm install package",
            "env -- npm install package",
            "command -- bun add package",
            "command -p bun add package",
        ):
            with self.subTest(command=command):
                ids = {
                    finding.rule_id
                    for finding in scan_text(
                        "\n".join(
                            [
                                "post_install() {",
                                f"    {command}",
                                "}",
                            ]
                        ),
                        filename="example.install",
                    )
                }

                self.assertIn("scriptlet-package-manager", ids)

    def test_command_query_does_not_match_package_manager_execution(self) -> None:
        ids = {
            finding.rule_id
            for finding in scan_text(
                "\n".join(
                    [
                        "post_install() {",
                        "    command -v bun",
                        "}",
                    ]
                ),
                filename="example.install",
            )
        }

        self.assertNotIn("scriptlet-package-manager", ids)

    def test_direct_exec_package_managers_are_high(self) -> None:
        for command in ("npx example", "bunx example", "npm exec example", "yarn dlx example", "pnpm exec example", "pnpm dlx example"):
            with self.subTest(command=command):
                finding = next(
                    finding
                    for finding in scan_text(command)
                    if finding.rule_id == "direct-exec-package-manager"
                )

                self.assertEqual(finding.severity, Severity.HIGH)

    def test_package_manager_aliases_are_detected(self) -> None:
        for command in ("npm i package", "bun i package"):
            with self.subTest(command=command):
                ids = {
                    finding.rule_id
                    for finding in scan_text(
                        "\n".join(
                            [
                                "post_install() {",
                                f"    {command}",
                                "}",
                            ]
                        ),
                        filename="example.install",
                    )
                }

                self.assertIn("scriptlet-package-manager", ids)

    def test_network_in_build_ignores_top_level_sources(self) -> None:
        ids = rule_ids('source=("https://example.com/file.tar.gz")')

        self.assertNotIn("network-in-build", ids)

    def test_network_in_build_context_ends_after_function(self) -> None:
        ids = rule_ids(
            "\n".join(
                [
                    "prepare() {",
                    "    true",
                    "}",
                    "curl https://example.com/file.tar.gz -o file.tar.gz",
                ]
            )
        )

        self.assertNotIn("network-in-build", ids)

    def test_writes_outside_pkgdir_is_detected(self) -> None:
        ids = rule_ids(
            "\n".join(
                [
                    "package() {",
                    "    install -Dm755 example /usr/bin/example",
                    "}",
                ]
            )
        )

        self.assertIn("writes-outside-pkgdir", ids)

    def test_writes_outside_pkgdir_allows_pkgdir_paths(self) -> None:
        ids = rule_ids(
            "\n".join(
                [
                    "package() {",
                    "    install -Dm755 example \"$pkgdir/usr/bin/example\"",
                    "    install -Dm644 example.conf \"${pkgdir}/etc/example.conf\"",
                    "}",
                ]
            )
        )

        self.assertNotIn("writes-outside-pkgdir", ids)

    def test_clean_input_produces_no_findings(self) -> None:
        text = (SAMPLES / "clean.PKGBUILD").read_text(encoding="utf-8")
        self.assertEqual(scan_text(text), [])

    def test_multiple_findings_are_returned(self) -> None:
        text = (SAMPLES / "suspicious.PKGBUILD").read_text(encoding="utf-8")
        ids = [finding.rule_id for finding in scan_text(text)]

        self.assertIn("checksum-skip", ids)
        self.assertIn("eval-used", ids)
        self.assertIn("setuid-permission", ids)
        self.assertGreaterEqual(len(ids), 5)

    def test_diff_added_lines_are_scanned(self) -> None:
        text = (SAMPLES / "suspicious.diff").read_text(encoding="utf-8")
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertIn("checksum-skip-added", ids)
        self.assertIn("eval-used", ids)
        self.assertIn("setuid-permission", ids)

    def test_diff_metadata_is_ignored(self) -> None:
        text = "+++ b/PKGBUILD\n@@ -1 +1 @@\n+eval \"$flags\"\n"
        lines = source_lines_from_diff(text)

        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].line_number, 1)
        self.assertEqual(lines[0].target_line_number, 1)
        self.assertEqual(lines[0].diff_line_number, 3)
        self.assertEqual(lines[0].filename, "PKGBUILD")
        self.assertEqual(lines[0].change_type, "added")
        self.assertEqual(lines[0].content, 'eval "$flags"')

    def test_diff_target_line_numbers_are_tracked(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -10,3 +20,4 @@",
                " context_before",
                "-old_checksum",
                "+eval \"$flags\"",
                " context_after",
                "+chmod 4755 \"$pkgdir/usr/bin/example\"",
            ]
        )
        lines = source_lines_from_diff(text)

        self.assertEqual([line.line_number for line in lines], [21, 23])
        self.assertEqual([line.target_line_number for line in lines], [21, 23])
        self.assertEqual([line.diff_line_number for line in lines], [7, 9])
        self.assertEqual([line.filename for line in lines], ["PKGBUILD", "PKGBUILD"])

    def test_diff_multi_file_filenames_are_tracked(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                "+eval \"$flags\"",
                "diff --git a/example.install b/example.install",
                "--- a/example.install",
                "+++ b/example.install",
                "@@ -3 +3 @@",
                "+systemctl start example.service",
            ]
        )
        findings = scan_diff_text(text)

        self.assertEqual(
            [(finding.filename, finding.line_number, finding.rule_id) for finding in findings],
            [
                ("PKGBUILD", 1, "eval-used"),
                ("example.install", 3, "privilege-command"),
            ],
        )

    def test_diff_contextual_rule_uses_visible_function_context(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,3 +1,4 @@",
                " prepare() {",
                "+    curl https://example.com/file.tar.gz -o file.tar.gz",
                " }",
            ]
        )
        findings = scan_diff_text(text)

        self.assertIn("network-in-build", {finding.rule_id for finding in findings})
        self.assertEqual(findings[0].function_name, "prepare")

    def test_diff_contextual_rule_ignores_top_level_source_url(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                '+source=("https://example.com/file.tar.gz")',
            ]
        )
        findings = scan_diff_text(text)

        self.assertNotIn("network-in-build", {finding.rule_id for finding in findings})

    def test_diff_source_change_findings_are_detected(self) -> None:
        text = (SAMPLES / "source-change.diff").read_text(encoding="utf-8")
        findings = scan_diff_text(text)
        ids = {finding.rule_id for finding in findings}

        self.assertIn("https-to-http-downgrade", ids)
        self.assertIn("source-domain-changed", ids)
        self.assertIn("source-url-added", ids)
        self.assertIn("checksum-skip-added", ids)

    def test_diff_source_change_findings_keep_old_and_new_values(self) -> None:
        text = (SAMPLES / "source-change.diff").read_text(encoding="utf-8")
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "source-domain-changed"
        )

        self.assertEqual(
            finding.old_value,
            "https://github.com/example/app/archive/v1.0.tar.gz",
        )
        self.assertEqual(
            finding.new_value,
            "http://downloads.example.net/app/v1.0.tar.gz",
        )
        self.assertEqual(finding.filename, "PKGBUILD")
        self.assertEqual(finding.line_number, 3)

    def test_diff_source_comparison_ignores_non_pkgbuild_files(self) -> None:
        text = "\n".join(
            [
                "diff --git a/example.install b/example.install",
                "--- a/example.install",
                "+++ b/example.install",
                "@@ -1 +1 @@",
                '-source=("https://github.com/example/app.tar.gz")',
                '+source=("http://strange.example/app.tar.gz")',
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertNotIn("source-domain-changed", ids)
        self.assertNotIn("https-to-http-downgrade", ids)

    def test_diff_multiline_source_arrays_are_compared(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,5 +1,5 @@",
                " source=(",
                '-  "https://github.com/example/app.tar.gz"',
                '+  "https://mirror.example/app.tar.gz"',
                " )",
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertIn("source-domain-changed", ids)

    def test_diff_removed_checksum_array_is_detected(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,4 +1,3 @@",
                " pkgname=example",
                " source=(\"https://example.com/app.tar.gz\")",
                "-sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
                " package() {",
            ]
        )
        findings = scan_diff_text(text)

        self.assertIn("checksum-array-removed", {finding.rule_id for finding in findings})

    def test_diff_checksum_algorithm_weakening_is_detected(self) -> None:
        text = (SAMPLES / "checksum-change.diff").read_text(encoding="utf-8")
        findings = scan_diff_text(text)
        ids = {finding.rule_id for finding in findings}

        self.assertIn("checksum-algorithm-weakened", ids)
        self.assertNotIn("checksum-array-removed", ids)

    def test_diff_checksum_algorithm_strengthening_is_ignored(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,4 +1,4 @@",
                " pkgname=example",
                " source=(\"https://example.com/app.tar.gz\")",
                "-md5sums=('abcdef0123456789abcdef0123456789')",
                "+sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
            ]
        )
        findings = scan_diff_text(text)

        self.assertNotIn("checksum-algorithm-weakened", {finding.rule_id for finding in findings})

    def test_diff_checksum_count_mismatch_is_detected(self) -> None:
        text = (SAMPLES / "checksum-change.diff").read_text(encoding="utf-8")
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "checksum-count-mismatch"
        )

        self.assertEqual(finding.severity.value, "MEDIUM")
        self.assertEqual(finding.old_value, "2")
        self.assertEqual(finding.new_value, "1")

    def test_diff_checksum_count_mismatch_matches_arch_suffixes(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,7 +1,7 @@",
                " pkgname=example",
                " source=(\"https://example.com/common.tar.gz\")",
                " sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
                " source_x86_64=(\"https://example.com/bin.tar.gz\")",
                "-sha256sums_x86_64=('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')",
                "+sha256sums_x86_64=('SKIP')",
            ]
        )
        findings = scan_diff_text(text)

        self.assertNotIn("checksum-count-mismatch", {finding.rule_id for finding in findings})

    def test_diff_vcs_checksum_skip_is_medium_without_duplicate_high(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,4 +1,4 @@",
                " pkgname=example-git",
                " source=(\"git+https://example.com/app.git\")",
                "-sha256sums=('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')",
                "+sha256sums=('SKIP')",
            ]
        )
        findings = scan_diff_text(text)
        skip_findings = [finding for finding in findings if "checksum-skip" in finding.rule_id]

        self.assertEqual([finding.rule_id for finding in skip_findings], ["checksum-skip-added"])
        self.assertEqual(skip_findings[0].severity.value, "MEDIUM")

    def test_diff_aliased_vcs_checksum_skip_is_medium(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,4 +1,4 @@",
                " pkgname=example-git",
                " source=(\"example::git+https://example.com/app\")",
                "-sha256sums=('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')",
                "+sha256sums=('SKIP')",
            ]
        )
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "checksum-skip-added"
        )

        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_diff_non_vcs_checksum_skip_stays_high(self) -> None:
        text = (SAMPLES / "checksum-change.diff").read_text(encoding="utf-8")
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "checksum-skip-added"
        )

        self.assertEqual(finding.severity.value, "HIGH")

    def test_diff_javascript_tooling_dependency_added_is_medium(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                "-depends=('foo')",
                "+depends=('foo' 'nodejs')",
            ]
        )
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "javascript-tooling-dependency-added"
        )

        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.new_value, "nodejs")

    def test_diff_unquoted_javascript_tooling_dependency_added_is_detected(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                "-depends=(foo)",
                "+depends=(foo bun)",
            ]
        )
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "javascript-tooling-dependency-added"
        )

        self.assertEqual(finding.new_value, "bun")

    def test_diff_multiline_unquoted_javascript_tooling_dependency_added_is_detected(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,4 +1,5 @@",
                " depends=(",
                "     foo",
                "+    bun",
                " )",
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertIn("javascript-tooling-dependency-added", ids)

    def test_diff_arch_specific_javascript_tooling_dependency_added_is_detected(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                "-makedepends_x86_64=(foo)",
                "+makedepends_x86_64=(foo nodejs)",
            ]
        )
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "javascript-tooling-dependency-added"
        )

        self.assertEqual(finding.new_value, "nodejs")
        self.assertIn("makedepends", finding.message)

    def test_diff_incremental_javascript_tooling_dependency_added_is_detected(self) -> None:
        for added_line, expected in (
            ("+depends+=(bun)", "bun"),
            ("+makedepends_x86_64+=(nodejs)", "nodejs"),
        ):
            with self.subTest(added_line=added_line):
                text = "\n".join(
                    [
                        "diff --git a/PKGBUILD b/PKGBUILD",
                        "--- a/PKGBUILD",
                        "+++ b/PKGBUILD",
                        "@@ -1 +1,2 @@",
                        " depends=(foo)",
                        added_line,
                    ]
                )
                finding = next(
                    finding
                    for finding in scan_diff_text(text)
                    if finding.rule_id == "javascript-tooling-dependency-added"
                )

                self.assertEqual(finding.new_value, expected)

    def test_diff_quoted_parentheses_in_dependency_values_are_preserved(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                "-optdepends=(foo)",
                "+optdepends=('nodejs: optional integration (experimental)' foo)",
            ]
        )
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "javascript-tooling-dependency-added"
        )

        self.assertEqual(finding.new_value, "nodejs")

    def test_diff_quoted_parentheses_in_source_values_are_preserved(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                '-source=("https://old.example/archive.tar.gz")',
                '+source=("https://example.org/archive_(x86_64).tar.gz")',
            ]
        )
        finding = next(
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "source-domain-changed"
        )

        self.assertEqual(finding.new_value, "https://example.org/archive_(x86_64).tar.gz")

    def test_diff_generic_dependency_added_is_not_reported(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                "-depends=(foo)",
                "+depends=(foo bar)",
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertNotIn("javascript-tooling-dependency-added", ids)

    def test_diff_dependency_move_is_not_runtime_addition(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,2 +1,2 @@",
                "-makedepends=('nodejs')",
                "+makedepends=()",
                "-depends=('foo')",
                "+depends=('foo' 'nodejs')",
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertIn("dependency-moved", ids)
        self.assertNotIn("javascript-tooling-dependency-added", ids)

    def test_diff_srcinfo_dependency_duplicate_is_deduplicated(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1 +1 @@",
                "-depends=('foo')",
                "+depends=('foo' 'bun')",
                "diff --git a/.SRCINFO b/.SRCINFO",
                "--- a/.SRCINFO",
                "+++ b/.SRCINFO",
                "@@ -1 +1,2 @@",
                " depends = foo",
                "+depends = bun",
            ]
        )
        findings = [
            finding
            for finding in scan_diff_text(text)
            if finding.rule_id == "javascript-tooling-dependency-added"
        ]

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].filename, "PKGBUILD")

    def test_diff_bun_campaign_variant_reports_composite_findings(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,2 +1,2 @@",
                "-depends=('pencil')",
                "+depends=('bun' 'pencil')",
                "-install=",
                "+install=pencil-android-lollipop-stencils-git-deps.install",
                "diff --git a/pencil-android-lollipop-stencils-git-deps.install b/pencil-android-lollipop-stencils-git-deps.install",
                "--- /dev/null",
                "+++ b/pencil-android-lollipop-stencils-git-deps.install",
                "@@ -0,0 +1,4 @@",
                "+post_install() {{",
                "+    cd /tmp",
                "+    bun add lodash js-digest",
                "+}}",
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertIn("install-script-added", ids)
        self.assertIn("scriptlet-package-manager", ids)
        self.assertIn("temporary-directory-package-install", ids)
        self.assertIn("javascript-tooling-dependency-added", ids)
        self.assertIn("suspicious-live-install-sequence", ids)

    def test_diff_pacman_hook_file_is_detected(self) -> None:
        text = "\n".join(
            [
                "diff --git a/example.hook b/example.hook",
                "--- /dev/null",
                "+++ b/example.hook",
                "@@ -0,0 +1,2 @@",
                "+[Action]",
                "+Exec = /bin/sh -c 'cd /tmp && npm install atomic-lockfile semver dotenv'",
            ]
        )
        ids = {finding.rule_id for finding in scan_diff_text(text)}

        self.assertIn("pacman-hook-added", ids)
        self.assertIn("pacman-hook-exec", ids)
        self.assertIn("scriptlet-package-manager", ids)


