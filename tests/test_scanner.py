from __future__ import annotations

import unittest
from collections.abc import Callable, Iterable

from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.scanner import scan_diff_text, scan_text, source_lines_from_diff, source_lines_from_text
from tests.helpers import SAMPLES, rule_ids


def lines(*values: str) -> str:
    return "\n".join(values)


def diff(
    *body: str, filename: str = "PKGBUILD", hunk: str = "@@ -1 +1 @@", new_file: bool = False
) -> str:
    return lines(
        f"diff --git a/{filename} b/{filename}", "--- /dev/null" if new_file else f"--- a/{filename}",
        f"+++ b/{filename}", hunk, *body,
    )


def findings_with(findings: Iterable[Finding], rule_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.rule_id == rule_id]


class ScannerTests(unittest.TestCase):
    def assert_detected(
        self, rule_id: str, text: str, *, filename: str | None = None, severity: Severity | None = None
    ) -> Finding:
        findings = scan_text(text, filename=filename)
        finding = next(finding for finding in findings if finding.rule_id == rule_id)
        if severity is not None:
            self.assertEqual(finding.severity, severity)
        return finding

    def assert_diff_finding(
        self, text: str, rule_id: str, *, severity: Severity | None = None,
        is_aur_package: Callable[[str], bool | None] | None = None,
    ) -> Finding:
        findings = scan_diff_text(text, is_aur_package=is_aur_package)
        matching = findings_with(findings, rule_id)
        self.assertEqual(len(matching), 1)
        if severity is not None:
            self.assertEqual(matching[0].severity, severity)
        return matching[0]

    def test_basic_rules_are_detected(self) -> None:
        cases = (
            ("eval", "eval-used", 'eval "$flags"'),
            ("curl-pipe", "curl-pipe-shell", "curl https://example.com/install.sh | bash"),
            ("wget-pipe", "curl-pipe-shell", "wget -O- https://example.com/install.sh | sh"),
            ("checksum-skip", "checksum-skip", "sha256sums=('SKIP')"),
            ("chmod-setuid", "setuid-permission", 'chmod 4755 "$pkgdir/usr/bin/example"'),
            ("install-setuid", "setuid-permission", 'install -Dm4755 helper "$pkgdir/usr/bin/helper"'),
            ("install-script", "install-script", "install=example.install"),
            ("bash-c", "shell-c", 'bash -c "$generated_command"'),
            ("sh-c", "shell-c", 'sh -c "echo test"'),
            ("source-relative", "source-command", "source ./extra.sh"),
            ("source-variable", "source-command", 'source "$srcdir/extra.sh"'),
            ("dot-source", "source-command", ". ./extra.sh"),
        )
        for name, rule_id, text in cases:
            with self.subTest(name=name):
                self.assertIn(rule_id, rule_ids(text))

    def test_command_rule_severities(self) -> None:
        cases = (
            ("base64", "decoded-pipe-shell", "base64 -d payload.txt | sh", Severity.HIGH),
            ("xxd", "decoded-pipe-shell", "xxd -r payload.hex | bash", Severity.HIGH),
            ("openssl", "decoded-pipe-shell", "openssl enc -d -in payload | sh", Severity.HIGH),
            ("python", "inline-interpreter-command", "python -c 'print(1)'", Severity.MEDIUM),
            ("perl", "inline-interpreter-command", "perl -e 'print 1'", Severity.MEDIUM),
            ("awk", "inline-interpreter-command", "awk '{ system($0) }'", Severity.MEDIUM),
            ("npx", "direct-exec-package-manager", "npx example", Severity.HIGH),
            ("bunx", "direct-exec-package-manager", "bunx example", Severity.HIGH),
            ("npm-exec", "direct-exec-package-manager", "npm exec example", Severity.HIGH),
            ("yarn-dlx", "direct-exec-package-manager", "yarn dlx example", Severity.HIGH),
            ("pnpm-exec", "direct-exec-package-manager", "pnpm exec example", Severity.HIGH),
            ("pnpm-dlx", "direct-exec-package-manager", "pnpm dlx example", Severity.HIGH),
        )
        for name, rule_id, command, severity in cases:
            with self.subTest(name=name):
                self.assert_detected(rule_id, command, severity=severity)

    def test_basic_false_positive_guards(self) -> None:
        source_cases = (
            ("srcinfo", "source = file::https://example.invalid/file", ".SRCINFO"),
            ("source-array", 'source=("https://example.invalid/file")', None),
            ("arch-source", 'source_x86_64=("https://example.invalid/file")', None),
            ("private-variable", '_source="https://example.invalid/file"', None),
        )
        for name, text, filename in source_cases:
            with self.subTest(name=name):
                ids = {finding.rule_id for finding in scan_text(text, filename=filename)}
                self.assertNotIn("source-command", ids)
        self.assertNotIn("decoded-pipe-shell", rule_ids("xxd -r payload.hex"))
        self.assertEqual(scan_text('# eval "$flags"\n# curl https://example.com/file | bash'), [])
        self.assertNotIn("network-in-build", rule_ids('source=("https://example.com/file.tar.gz")'))

    def test_checksum_skip_uses_source_context(self) -> None:
        cases = (
            (
                "vcs",
                lines('source=("git+https://example.invalid/project.git")', "sha256sums=('SKIP')"),
                Severity.MEDIUM,
                2,
            ),
            (
                "aliased-vcs",
                lines('source=("project::git+https://example.invalid/project")', "sha256sums=('SKIP')"),
                Severity.MEDIUM,
                2,
            ),
            (
                "archive",
                lines('source=("https://example.invalid/project.tar.gz")', "sha256sums=('SKIP')"),
                Severity.HIGH,
                2,
            ),
            ("unknown", "sha256sums=('SKIP')", Severity.HIGH, 1),
            (
                "multiline-vcs",
                lines(
                    "source=(",
                    '  "git+https://example.invalid/project.git"',
                    ")",
                    "sha256sums=(",
                    "  'SKIP'",
                    ")",
                ),
                Severity.MEDIUM,
                5,
            ),
            (
                "arch-vcs",
                lines(
                    'source=("https://example.invalid/common.tar.gz")',
                    "sha256sums=('abc')",
                    'source_x86_64=("git+https://example.invalid/project.git")',
                    "sha256sums_x86_64=('SKIP')",
                ),
                Severity.MEDIUM,
                4,
            ),
        )
        for name, text, severity, line_number in cases:
            with self.subTest(name=name):
                finding = self.assert_detected("checksum-skip", text, severity=severity)
                self.assertEqual(finding.line_number, line_number)

    def test_function_context_is_tracked(self) -> None:
        source = lines(
            "pkgname=example",
            "prepare() {",
            "    curl https://example.com/file.tar.gz -o file.tar.gz",
            "}",
            "pkgver=1.0",
            "function package {",
            '    install -Dm755 example "$pkgdir/usr/bin/example"',
            "}",
            "pkgrel=1",
        )
        actual = [line.function_name for line in source_lines_from_text(source)]
        self.assertEqual(actual, [None, "prepare", "prepare", "prepare", None, "package", "package", "package", None])

    def test_pkgbuild_contextual_rules_and_guards(self) -> None:
        cases = (
            (
                "network-in-build",
                lines(
                    "prepare() {",
                    "    curl https://example.com/file.tar.gz -o file.tar.gz",
                    "    git clone https://example.com/repo.git",
                    "    npm install",
                    "}",
                ),
                "network-in-build",
                True,
            ),
            (
                "context-ends",
                lines("prepare() {", "    true", "}", "curl https://example.com/file.tar.gz -o file.tar.gz"),
                "network-in-build",
                False,
            ),
            (
                "outside-pkgdir",
                lines("package() {", "    install -Dm755 example /usr/bin/example", "}"),
                "writes-outside-pkgdir",
                True,
            ),
            (
                "inside-pkgdir",
                lines(
                    "package() {",
                    '    install -Dm755 example "$pkgdir/usr/bin/example"',
                    '    install -Dm644 example.conf "${pkgdir}/etc/example.conf"',
                    "}",
                ),
                "writes-outside-pkgdir",
                False,
            ),
        )
        for name, text, rule_id, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(rule_id in rule_ids(text), expected)

    def test_scriptlet_and_hook_package_manager_context(self) -> None:
        cases = (
            (
                "bun-temp-scriptlet",
                lines("post_install() {{", "    cd /tmp", "    bun add lodash js-digest", "}}"),
                "example.install",
                {"scriptlet-package-manager", "temporary-directory-package-install"},
            ),
            (
                "npm-temp-scriptlet",
                lines("post_install() {", "    cd /tmp", "    npm install atomic-lockfile yargs", "}"),
                "example.install",
                {"scriptlet-package-manager", "temporary-directory-package-install"},
            ),
            (
                "hook",
                lines("[Action]", "Exec = /bin/sh -c 'cd /tmp && npm install atomic-lockfile semver dotenv'"),
                "example.hook",
                {"pacman-hook-exec", "scriptlet-package-manager", "temporary-directory-package-install"},
            ),
        )
        for name, text, filename, expected in cases:
            with self.subTest(name=name):
                findings = scan_text(text, filename=filename)
                self.assertTrue(expected <= {finding.rule_id for finding in findings})
                context = "hook" if filename.endswith(".hook") else "scriptlet"
                self.assertTrue(all(finding.execution_context == context for finding in findings))
        finding = self.assert_detected(
            "scriptlet-package-manager",
            lines("function post_install {", "    npm install atomic-lockfile", "}"),
            filename="example.install",
        )
        self.assertEqual((finding.function_name, finding.execution_context), ("post_install", "scriptlet"))

    def test_scriptlet_package_manager_false_positive_guards(self) -> None:
        cases = (
            (
                "legitimate-scriptlet",
                lines(
                    "post_install() {",
                    '    echo "Custom flags belong in ~/.config/example-flags.conf"',
                    "}",
                    "",
                    "post_upgrade() {",
                    "    post_install",
                    "}",
                ),
            ),
            ("comments-and-strings", lines("# npm install atomic-lockfile", 'message="run bun add manually"')),
            (
                "assignment-in-scriptlet",
                lines("post_install() {", '    message="run bun add manually"', "}"),
            ),
            ("command-query", lines("post_install() {", "    command -v bun", "}")),
        )
        for name, text in cases:
            with self.subTest(name=name):
                findings = scan_text(text, filename="example.install")
                self.assertNotIn("scriptlet-package-manager", {finding.rule_id for finding in findings})
                if name == "legitimate-scriptlet":
                    self.assertFalse(any(finding.severity == Severity.HIGH for finding in findings))
                if name == "comments-and-strings":
                    self.assertEqual(findings, [])

    def test_scriptlet_diff_context(self) -> None:
        install_hunk = lines(
            "--- a/example.install",
            "+++ b/example.install",
            "@@ -40,4 +40,5 @@",
            "     existing_command",
            "+    npm install suspicious-package",
            " }",
        )
        finding = findings_with(scan_diff_text(install_hunk), "scriptlet-package-manager")[0]
        self.assertIsNone(finding.function_name)
        self.assertEqual(finding.execution_context, "scriptlet")

        custom_hunk = lines(
            "--- a/example-deps",
            "+++ b/example-deps",
            "@@ -1 +1 @@",
            "+npm install suspicious-package",
        )
        ids = {finding.rule_id for finding in scan_diff_text(custom_hunk, scriptlet_files={"example-deps"})}
        self.assertIn("scriptlet-package-manager", ids)

    def test_one_line_scriptlet_does_not_leak_function_name(self) -> None:
        findings = scan_text(
            lines('post_install() { echo "done"; }', "npm install suspicious-package"),
            filename="example.install",
        )
        matching = findings_with(findings, "scriptlet-package-manager")
        self.assertEqual(len(matching), 1)
        self.assertIsNone(matching[0].function_name)
        self.assertEqual(matching[0].execution_context, "scriptlet")

    def test_hook_shell_payload_variants(self) -> None:
        for line in ("Exec = /bin/sh -c 'npm install package'", 'Exec=/usr/bin/bash -c "bun add package"'):
            with self.subTest(line=line):
                ids = {finding.rule_id for finding in scan_text(line, filename="example.hook")}
                self.assertTrue({"pacman-hook-exec", "scriptlet-package-manager"} <= ids)

    def test_temporary_directory_tracking(self) -> None:
        cases = (
            (
                "cleared-by-cd",
                lines("post_install() {", "    cd /tmp", "    prepare_something", "    cd /usr/share/example", "    npm install package", "}"),
                False,
            ),
            ("tmp-subdir", lines("post_install() {", "    cd /tmp/payload", "    npm install package", "}"), True),
            ("var-tmp-subdir", lines("post_install() {", "    cd /var/tmp/build-dir", "    bun add package", "}"), True),
            ("cd-after-install", lines("post_install() {", "    npm install package && cd /tmp", "}"), False),
            (
                "leave-tmp-before-install",
                lines("post_install() {", "    cd /tmp && cd /usr/share/example && npm install package", "}"),
                False,
            ),
        )
        for name, text, temporary in cases:
            with self.subTest(name=name):
                ids = {finding.rule_id for finding in scan_text(text, filename="example.install")}
                self.assertIn("scriptlet-package-manager", ids)
                self.assertEqual("temporary-directory-package-install" in ids, temporary)

        hook = lines("[Action]", "Exec = /bin/sh -c 'cd /tmp'", "Exec = /bin/sh -c 'npm install package'")
        ids = {finding.rule_id for finding in scan_text(hook, filename="example.hook")}
        self.assertIn("scriptlet-package-manager", ids)
        self.assertNotIn("temporary-directory-package-install", ids)

    def test_package_manager_command_forms(self) -> None:
        commands = (
            "env HOME=/tmp npm install package",
            "env -i npm install package",
            "env -- npm install package",
            "command -- bun add package",
            "command -p bun add package",
            "npm i package",
            "bun i package",
        )
        for command in commands:
            with self.subTest(command=command):
                text = lines("post_install() {", f"    {command}", "}")
                self.assertIn(
                    "scriptlet-package-manager",
                    {finding.rule_id for finding in scan_text(text, filename="example.install")},
                )

        absolute_forms = lines(
            "post_install() {",
            "    cd /tmp && /usr/bin/npm install atomic-lockfile",
            "    /usr/bin/bun add js-digest",
            "    env npm install atomic-lockfile",
            "    command bun add js-digest",
            "}",
        )
        ids = {finding.rule_id for finding in scan_text(absolute_forms, filename="example.install")}
        self.assertTrue({"scriptlet-package-manager", "temporary-directory-package-install"} <= ids)

    def test_sample_scans(self) -> None:
        clean = (SAMPLES / "clean.PKGBUILD").read_text(encoding="utf-8")
        self.assertEqual(scan_text(clean), [])
        suspicious = (SAMPLES / "suspicious.PKGBUILD").read_text(encoding="utf-8")
        ids = [finding.rule_id for finding in scan_text(suspicious)]
        self.assertTrue({"checksum-skip", "eval-used", "setuid-permission"} <= set(ids))
        self.assertGreaterEqual(len(ids), 5)

    def test_diff_added_lines_are_scanned(self) -> None:
        text = (SAMPLES / "suspicious.diff").read_text(encoding="utf-8")
        ids = {finding.rule_id for finding in scan_diff_text(text)}
        self.assertTrue({"checksum-skip-added", "eval-used", "setuid-permission"} <= ids)

    def test_diff_line_metadata(self) -> None:
        parsed = source_lines_from_diff('+++ b/PKGBUILD\n@@ -1 +1 @@\n+eval "$flags"\n')
        self.assertEqual(len(parsed), 1)
        line = parsed[0]
        self.assertEqual(
            (line.line_number, line.target_line_number, line.diff_line_number, line.filename, line.change_type, line.content),
            (1, 1, 3, "PKGBUILD", "added", 'eval "$flags"'),
        )

        parsed = source_lines_from_diff(
            diff(
                " context_before",
                "-old_checksum",
                '+eval "$flags"',
                " context_after",
                '+chmod 4755 "$pkgdir/usr/bin/example"',
                hunk="@@ -10,3 +20,4 @@",
            )
        )
        self.assertEqual([line.line_number for line in parsed], [21, 23])
        self.assertEqual([line.target_line_number for line in parsed], [21, 23])
        self.assertEqual([line.diff_line_number for line in parsed], [7, 9])
        self.assertEqual([line.filename for line in parsed], ["PKGBUILD", "PKGBUILD"])

    def test_diff_multi_file_filenames_are_tracked(self) -> None:
        text = lines(
            diff('+eval "$flags"'),
            diff("+systemctl start example.service", filename="example.install", hunk="@@ -3 +3 @@"),
        )
        findings = scan_diff_text(text)
        self.assertEqual(
            [(finding.filename, finding.line_number, finding.rule_id) for finding in findings],
            [("PKGBUILD", 1, "eval-used"), ("example.install", 3, "privilege-command")],
        )

    def test_diff_function_context(self) -> None:
        contextual = diff(
            " prepare() {",
            "+    curl https://example.com/file.tar.gz -o file.tar.gz",
            " }",
            hunk="@@ -1,3 +1,4 @@",
        )
        finding = self.assert_diff_finding(contextual, "network-in-build")
        self.assertEqual(finding.function_name, "prepare")

        top_level = diff('+source=("https://example.com/file.tar.gz")')
        self.assertNotIn("network-in-build", {finding.rule_id for finding in scan_diff_text(top_level)})

    def test_source_change_fixture(self) -> None:
        findings = scan_diff_text((SAMPLES / "source-change.diff").read_text(encoding="utf-8"))
        ids = {finding.rule_id for finding in findings}
        self.assertTrue({"https-to-http-downgrade", "source-domain-changed", "source-url-added", "checksum-skip-added"} <= ids)
        finding = findings_with(findings, "source-domain-changed")[0]
        self.assertEqual(finding.old_value, "https://github.com/example/app/archive/v1.0.tar.gz")
        self.assertEqual(finding.new_value, "http://downloads.example.net/app/v1.0.tar.gz")
        self.assertEqual((finding.filename, finding.line_number), ("PKGBUILD", 3))

    def test_source_diff_parsing_variants(self) -> None:
        cases = (
            (
                "ignore-install-file",
                diff(
                    '-source=("https://github.com/example/app.tar.gz")',
                    '+source=("http://strange.example/app.tar.gz")',
                    filename="example.install",
                ),
                set(),
                {"source-domain-changed", "https-to-http-downgrade"},
            ),
            (
                "multiline",
                diff(
                    " source=(",
                    '-  "https://github.com/example/app.tar.gz"',
                    '+  "https://mirror.example/app.tar.gz"',
                    " )",
                    hunk="@@ -1,5 +1,5 @@",
                ),
                {"source-domain-changed"},
                set(),
            ),
            (
                "quoted-parentheses",
                diff(
                    '-source=("https://old.example/archive.tar.gz")',
                    '+source=("https://example.org/archive_(x86_64).tar.gz")',
                ),
                {"source-domain-changed"},
                set(),
            ),
        )
        for name, text, present, absent in cases:
            with self.subTest(name=name):
                findings = scan_diff_text(text)
                ids = {finding.rule_id for finding in findings}
                self.assertTrue(present <= ids)
                self.assertTrue(absent.isdisjoint(ids))
                if name == "quoted-parentheses":
                    self.assertEqual(
                        findings_with(findings, "source-domain-changed")[0].new_value,
                        "https://example.org/archive_(x86_64).tar.gz",
                    )

    def test_checksum_diff_changes(self) -> None:
        fixture_findings = scan_diff_text((SAMPLES / "checksum-change.diff").read_text(encoding="utf-8"))
        fixture_ids = {finding.rule_id for finding in fixture_findings}
        self.assertIn("checksum-algorithm-weakened", fixture_ids)
        self.assertNotIn("checksum-array-removed", fixture_ids)
        mismatch = findings_with(fixture_findings, "checksum-count-mismatch")[0]
        self.assertEqual((mismatch.severity, mismatch.old_value, mismatch.new_value), (Severity.MEDIUM, "2", "1"))
        self.assertEqual(findings_with(fixture_findings, "checksum-skip-added")[0].severity, Severity.HIGH)

        removed = diff(
            " pkgname=example",
            ' source=("https://example.com/app.tar.gz")',
            "-sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
            " package() {",
            hunk="@@ -1,4 +1,3 @@",
        )
        self.assertIn("checksum-array-removed", {finding.rule_id for finding in scan_diff_text(removed)})

        strengthened = diff(
            " pkgname=example",
            ' source=("https://example.com/app.tar.gz")',
            "-md5sums=('abcdef0123456789abcdef0123456789')",
            "+sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
            hunk="@@ -1,4 +1,4 @@",
        )
        self.assertNotIn("checksum-algorithm-weakened", {finding.rule_id for finding in scan_diff_text(strengthened)})

        arch = diff(
            " pkgname=example",
            ' source=("https://example.com/common.tar.gz")',
            " sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')",
            ' source_x86_64=("https://example.com/bin.tar.gz")',
            "-sha256sums_x86_64=('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')",
            "+sha256sums_x86_64=('SKIP')",
            hunk="@@ -1,7 +1,7 @@",
        )
        self.assertNotIn("checksum-count-mismatch", {finding.rule_id for finding in scan_diff_text(arch)})

    def test_diff_checksum_skip_source_context(self) -> None:
        cases = (
            ("vcs", ' source=("git+https://example.com/app.git")'),
            ("aliased-vcs", ' source=("example::git+https://example.com/app")'),
        )
        checksum = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        for name, source in cases:
            with self.subTest(name=name):
                text = diff(
                    " pkgname=example-git",
                    source,
                    f"-sha256sums=('{checksum}')",
                    "+sha256sums=('SKIP')",
                    hunk="@@ -1,4 +1,4 @@",
                )
                findings = scan_diff_text(text)
                matching = [finding for finding in findings if "checksum-skip" in finding.rule_id]
                self.assertEqual([finding.rule_id for finding in matching], ["checksum-skip-added"])
                self.assertEqual(matching[0].severity, Severity.MEDIUM)

    def test_javascript_dependency_syntax_variants(self) -> None:
        cases = (
            ("quoted", ("-depends=('foo')", "+depends=('foo' 'nodejs')"), "nodejs", None),
            ("unquoted", ("-depends=(foo)", "+depends=(foo bun)"), "bun", None),
            ("multiline", (" depends=(", "     foo", "+    bun", " )"), "bun", None),
            (
                "arch-specific",
                ("-makedepends_x86_64=(foo)", "+makedepends_x86_64=(foo nodejs)"),
                "nodejs",
                "makedepends",
            ),
            ("incremental", (" depends=(foo)", "+depends+=(bun)"), "bun", None),
            (
                "incremental-arch",
                (" depends=(foo)", "+makedepends_x86_64+=(nodejs)"),
                "nodejs",
                "makedepends",
            ),
            (
                "quoted-parentheses",
                ("-optdepends=(foo)", "+optdepends=('nodejs: optional integration (experimental)' foo)"),
                "nodejs",
                None,
            ),
        )
        for name, body, expected, message_part in cases:
            with self.subTest(name=name):
                finding = self.assert_diff_finding(diff(*body), "javascript-tooling-dependency-added", severity=Severity.MEDIUM)
                self.assertEqual(finding.new_value, expected)
                if message_part:
                    self.assertIn(message_part, finding.message)

    def test_dependency_addition_groups(self) -> None:
        cases = (
            ("depends", "depends", "foo", "bar"),
            ("makedepends", "makedepends", "git", "cmake"),
            ("checkdepends", "checkdepends", "foo", "bar"),
            ("optdepends", "optdepends", "foo", "bar"),
            ("arch", "depends_x86_64", "foo", "bar"),
        )
        for name, group, existing, added in cases:
            with self.subTest(name=name):
                text = diff(f"-{group}=({existing})", f"+{group}=({existing} {added})")
                finding = self.assert_diff_finding(text, "dependency-added", severity=Severity.LOW)
                self.assertEqual(finding.new_value, added)
                self.assertNotIn("javascript-tooling-dependency-added", {item.rule_id for item in scan_diff_text(text)})

    def test_dependency_classification(self) -> None:
        cases = (
            ("build-tool", "cargo", "build-tool-dependency-added", Severity.MEDIUM, None),
            ("aur-heuristic", "bar-git", "aur-dependency-added", Severity.MEDIUM, None),
            (
                "aur-callable",
                "unknown-aur-pkg",
                "aur-dependency-added",
                Severity.MEDIUM,
                lambda package: package == "unknown-aur-pkg",
            ),
            (
                "official-callable",
                "bash",
                "dependency-added",
                Severity.LOW,
                lambda package: False if package == "bash" else True,
            ),
        )
        for name, dependency, rule_id, severity, checker in cases:
            with self.subTest(name=name):
                text = diff("-depends=(foo)", f"+depends=(foo {dependency})")
                finding = self.assert_diff_finding(text, rule_id, severity=severity, is_aur_package=checker)
                self.assertEqual(finding.new_value, dependency)

        ids = {finding.rule_id for finding in scan_diff_text(diff("-depends=(foo)", "+depends=(foo cargo-git)"))}
        self.assertIn("aur-dependency-added", ids)
        self.assertNotIn("build-tool-dependency-added", ids)

    def test_dependency_moves_and_removals(self) -> None:
        javascript_move = diff(
            "-makedepends=('nodejs')",
            "+makedepends=()",
            "-depends=('foo')",
            "+depends=('foo' 'nodejs')",
            hunk="@@ -1,2 +1,2 @@",
        )
        ids = {finding.rule_id for finding in scan_diff_text(javascript_move)}
        self.assertIn("dependency-moved", ids)
        self.assertNotIn("javascript-tooling-dependency-added", ids)

        removed = self.assert_diff_finding(
            diff("-depends=(foo bar)", "+depends=(foo)"),
            "dependency-removed",
            severity=Severity.LOW,
        )
        self.assertEqual(removed.old_value, "bar")

        generic_move = diff(
            "-makedepends=(bar)",
            "+makedepends=()",
            "-depends=(foo)",
            "+depends=(foo bar)",
            hunk="@@ -1,2 +1,2 @@",
        )
        findings = scan_diff_text(generic_move)
        self.assert_diff_finding(generic_move, "dependency-moved", severity=Severity.LOW)
        self.assertNotIn("dependency-added", {finding.rule_id for finding in findings})

    def test_srcinfo_dependency_changes_and_deduplication(self) -> None:
        cases = (
            ("generic", "+depends = bar", "dependency-added", "bar", Severity.LOW),
            ("build-tool", "+makedepends = cargo", "build-tool-dependency-added", "cargo", Severity.MEDIUM),
            ("aur", "+depends = bar-bin", "aur-dependency-added", "bar-bin", Severity.MEDIUM),
        )
        for name, added_line, rule_id, value, severity in cases:
            with self.subTest(name=name):
                text = diff(" depends = foo", added_line, filename=".SRCINFO", hunk="@@ -1 +1,2 @@")
                finding = self.assert_diff_finding(text, rule_id, severity=severity)
                self.assertEqual(finding.new_value, value)

        for dependency, rule_id in (("bar", "dependency-added"), ("bun", "javascript-tooling-dependency-added")):
            with self.subTest(deduplicated=dependency):
                pkgbuild = diff("-depends=('foo')", f"+depends=('foo' '{dependency}')")
                srcinfo = diff(" depends = foo", f"+depends = {dependency}", filename=".SRCINFO", hunk="@@ -1 +1,2 @@")
                findings = findings_with(scan_diff_text(lines(pkgbuild, srcinfo)), rule_id)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].filename, "PKGBUILD")

    def test_dependency_risk_correlations(self) -> None:
        install_change = lines(
            diff("-depends=(foo)", "+depends=(foo bar)", "-install=", "+install=example.install", hunk="@@ -1,2 +1,2 @@"),
            diff("+#!/bin/bash", filename="example.install", hunk="@@ -0,0 +1 @@", new_file=True),
        )
        findings = scan_diff_text(install_change)
        ids = {finding.rule_id for finding in findings}
        self.assertTrue(
            {"dependency-added", "install-script-added", "aur-metadata-executable-added", "dependency-with-risk-signals"} <= ids
        )
        self.assertEqual(findings_with(findings, "dependency-with-risk-signals")[0].severity, Severity.HIGH)

        source_change = diff(
            "-depends=(foo)",
            "+depends=(foo bar)",
            "-source=('https://old.example/file.tar.gz')",
            "+source=('https://new.example/file.tar.gz')",
            "-sha256sums=('abc')",
            "+sha256sums=('def')",
            hunk="@@ -1,3 +1,3 @@",
        )
        findings = scan_diff_text(source_change)
        ids = {finding.rule_id for finding in findings}
        self.assertTrue({"dependency-added", "source-domain-changed", "dependency-with-risk-signals"} <= ids)
        self.assertEqual(findings_with(findings, "dependency-with-risk-signals")[0].severity, Severity.HIGH)

        plain = diff("-depends=(foo)", "+depends=(foo bar)")
        self.assertNotIn("dependency-with-risk-signals", {finding.rule_id for finding in scan_diff_text(plain)})

    def test_composite_live_install_and_hook_diffs(self) -> None:
        campaign = lines(
            diff(
                "-depends=('pencil')",
                "+depends=('bun' 'pencil')",
                "-install=",
                "+install=pencil-android-lollipop-stencils-git-deps.install",
                hunk="@@ -1,2 +1,2 @@",
            ),
            diff(
                "+post_install() {{",
                "+    cd /tmp",
                "+    bun add lodash js-digest",
                "+}}",
                filename="pencil-android-lollipop-stencils-git-deps.install",
                hunk="@@ -0,0 +1,4 @@",
                new_file=True,
            ),
        )
        ids = {finding.rule_id for finding in scan_diff_text(campaign)}
        self.assertTrue(
            {
                "install-script-added",
                "scriptlet-package-manager",
                "temporary-directory-package-install",
                "javascript-tooling-dependency-added",
                "suspicious-live-install-sequence",
            }
            <= ids
        )

        hook = diff(
            "+[Action]",
            "+Exec = /bin/sh -c 'cd /tmp && npm install atomic-lockfile semver dotenv'",
            filename="example.hook",
            hunk="@@ -0,0 +1,2 @@",
            new_file=True,
        )
        ids = {finding.rule_id for finding in scan_diff_text(hook)}
        self.assertTrue({"pacman-hook-added", "pacman-hook-exec", "scriptlet-package-manager"} <= ids)
