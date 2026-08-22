from __future__ import annotations

import unittest

from aur_diff_sentinel.metadata_diff import find_added_metadata_files
from aur_diff_sentinel.pkgbuild_syntax import filename_from_diff_header
from aur_diff_sentinel.unified_diff import iter_diff_files, iter_diff_lines


class UnifiedDiffTests(unittest.TestCase):
    def test_iter_diff_lines_tracks_files_hunks_and_line_numbers(self) -> None:
        text = "\n".join(
            [
                "diff --git a/PKGBUILD b/PKGBUILD",
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -2,2 +2,3 @@",
                " pkgname=example",
                "-pkgver=1.0",
                "+pkgver=1.1",
                "+install=example.install",
            ]
        )

        lines = list(iter_diff_lines(text))

        self.assertEqual(
            [(line.change_type, line.filename, line.line_number, line.content) for line in lines],
            [
                ("context", "PKGBUILD", 2, "pkgname=example"),
                ("removed", "PKGBUILD", 3, "pkgver=1.0"),
                ("added", "PKGBUILD", 3, "pkgver=1.1"),
                ("added", "PKGBUILD", 4, "install=example.install"),
            ],
        )
        self.assertEqual({line.hunk_index for line in lines}, {1})

    def test_iter_diff_lines_marks_new_files(self) -> None:
        text = "\n".join(
            [
                "diff --git a/example.install b/example.install",
                "--- /dev/null",
                "+++ b/example.install",
                "@@ -0,0 +1,2 @@",
                "+post_install() {",
                "+}",
            ]
        )

        lines = list(iter_diff_lines(text))

        self.assertTrue(all(line.file.is_new_file for line in lines))
        self.assertEqual([line.line_number for line in lines], [1, 2])
        self.assertEqual([line.filename for line in lines], ["example.install", "example.install"])

    def test_iter_diff_lines_keeps_deleted_file_name_with_fallback(self) -> None:
        text = "\n".join(
            [
                "diff --git a/example.install b/example.install",
                "--- a/example.install",
                "+++ /dev/null",
                "@@ -1 +0,0 @@",
                "-post_install() { :; }",
            ]
        )

        lines = list(iter_diff_lines(text, fallback_filename="update.diff"))

        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].filename, "example.install")
        self.assertTrue(lines[0].file.is_deleted_file)

    def test_filename_from_diff_header_strips_old_and_new_prefixes(self) -> None:
        self.assertEqual(filename_from_diff_header("--- a/PKGBUILD"), "PKGBUILD")
        self.assertEqual(filename_from_diff_header("+++ b/PKGBUILD"), "PKGBUILD")

    def test_iter_diff_files_reports_header_only_added_metadata(self) -> None:
        text = "\n".join(
            [
                "diff --git a/example.install b/example.install",
                "--- /dev/null",
                "+++ b/example.install",
                "diff --git a/example.hook b/example.hook",
                "--- /dev/null",
                "+++ b/example.hook",
            ]
        )

        files = list(iter_diff_files(text))
        findings = find_added_metadata_files(text)

        self.assertEqual([file.filename for file in files], ["example.install", "example.hook"])
        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["install-script-added", "pacman-hook-added"],
        )

    def test_header_like_content_inside_hunk_is_not_parsed_as_file_metadata(self) -> None:
        text = "\n".join(
            [
                "--- a/PKGBUILD",
                "+++ b/PKGBUILD",
                "@@ -1,2 +1,2 @@",
                "---removed",
                "+++added",
                "--- removed with space",
                "+++ added with space",
            ]
        )

        lines = list(iter_diff_lines(text))

        self.assertEqual(
            [(line.change_type, line.content) for line in lines],
            [
                ("removed", "--removed"),
                ("added", "++added"),
                ("removed", "-- removed with space"),
                ("added", "++ added with space"),
            ],
        )
        self.assertEqual([file.filename for file in iter_diff_files(text)], ["PKGBUILD"])

    def test_hunk_counts_allow_multiple_hunks_and_files_without_git_markers(self) -> None:
        text = "\n".join(
            [
                "--- a/first.install",
                "+++ b/first.install",
                "@@ -1 +1 @@",
                "-old one",
                "+new one",
                "@@ -4 +4 @@",
                "-old two",
                "+new two",
                "--- a/second.hook",
                "+++ b/second.hook",
                "@@ -0,0 +1 @@",
                "+new file content",
            ]
        )

        lines = list(iter_diff_lines(text))

        self.assertEqual(
            [file.filename for file in iter_diff_files(text)],
            ["first.install", "second.hook"],
        )
        self.assertEqual(
            [(line.filename, line.hunk_index, line.content) for line in lines],
            [
                ("first.install", 1, "old one"),
                ("first.install", 1, "new one"),
                ("first.install", 2, "old two"),
                ("first.install", 2, "new two"),
                ("second.hook", 3, "new file content"),
            ],
        )

    def test_header_prefixes_without_separator_are_ignored(self) -> None:
        text = "---not-a-header\n+++not-a-header"

        self.assertEqual(list(iter_diff_files(text)), [])
        self.assertEqual(list(iter_diff_lines(text)), [])


if __name__ == "__main__":
    unittest.main()
