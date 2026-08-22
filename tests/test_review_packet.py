from __future__ import annotations

import unittest

from aur_diff_sentinel.explanations import EXPLANATIONS
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.provider import AurUpdate
from aur_diff_sentinel.report import format_review_packet
from aur_diff_sentinel.update_review import PackageReview, UpdateReviewResult


def packet_finding(
    rule_id: str,
    severity: Severity,
    *,
    filename: str = "PKGBUILD",
    message: str | None = None,
    line_content: str = "changed line",
    old_value: str | None = None,
    new_value: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message or rule_id,
        line_number=7,
        line_content=line_content,
        hint="inspect it",
        filename=filename,
        old_value=old_value,
        new_value=new_value,
    )


class ReviewPacketTests(unittest.TestCase):
    def test_packet_is_complete_ordered_and_deduplicated(self) -> None:
        clean = PackageReview(AurUpdate("clean-pkg", "1.0-1", "1.1-1"))
        risky = PackageReview(
            AurUpdate("risky-pkg", "2.0-1", "2.1-1"),
            findings=[
                packet_finding(
                    "source-domain-changed",
                    Severity.HIGH,
                    filename="z.install",
                    old_value="https://old.example/archive",
                    new_value="https://new.example/archive",
                ),
                packet_finding(
                    "source-domain-changed",
                    Severity.HIGH,
                    filename="PKGBUILD",
                ),
                packet_finding("install-script", Severity.MEDIUM, filename="PKGBUILD"),
            ],
        )

        packet = format_review_packet(UpdateReviewResult([clean, risky]))

        for text in (
            "# aur-diff-sentinel review packet",
            "not a verdict that a package is safe or malicious",
            "- **Updates:** 2",
            "- **Packages with findings:** 1",
            "- **Incomplete analyses:** 0",
            "- **Maximum severity:** HIGH",
            "- **AUR:** https://aur.archlinux.org/packages/risky-pkg",
            "- **Analysis:** complete",
            "- **Attention:** NONE",
            "- **Attention:** HIGH",
            "No configured patterns were detected in the available analysis for this package. "
            "Manual review is still required.",
            "No packages were updated.",
        ):
            self.assertIn(text, packet)
        self.assertLess(packet.index("## Package: clean-pkg"), packet.index("## Package: risky-pkg"))

        risky_section = packet.split("## Package: risky-pkg", 1)[1]
        self.assertLess(risky_section.index("#### HIGH"), risky_section.index("#### MEDIUM"))
        files_section = risky_section.split("### Files to inspect", 1)[1].split(
            "### Manual review checklist", 1
        )[0]
        self.assertEqual(files_section.count("- PKGBUILD"), 1)
        self.assertEqual(files_section.count("- z.install"), 1)
        self.assertLess(files_section.index("- PKGBUILD"), files_section.index("- z.install"))
        self.assertEqual(
            risky_section.count(EXPLANATIONS["source-domain-changed"].inspect),
            1,
        )
        self.assertEqual(risky_section.count(EXPLANATIONS["install-script"].inspect), 1)

    def test_packet_escapes_markdown_and_isolates_untrusted_evidence(self) -> None:
        review = PackageReview(
            AurUpdate("example_pkg+", "1.0_[old]", "1.1_*new*"),
            findings=[
                packet_finding(
                    "source-domain-changed",
                    Severity.HIGH,
                    filename="dir_name/PKG[BUILD]",
                    message="Changed *source* [link] <tag> # heading | cell ~strike~ `code`",
                    line_content="<script>*untrusted*</script>\n# injected heading",
                    old_value="[old](https://old.example)",
                    new_value="__new__",
                )
            ],
            notes=["Review *this* [note]\non the next line."],
            analysis_errors=["candidate <bad> _error_"],
        )

        packet = format_review_packet(UpdateReviewResult([review]))

        for text in (
            r"## Package: example\_pkg+",
            "https://aur.archlinux.org/packages/example_pkg+",
            r"- **Previous version:** 1.0\_\[old\]",
            r"- **Candidate version:** 1.1\_\*new\*",
            r"- Review \*this\* \[note\] on the next line.",
            r"- candidate \<bad\> \_error\_",
            r"- **Location:** dir\_name/PKG\[BUILD\]:7",
            r"- **Message:** Changed \*source\* \[link\] \<tag\> \# heading \| cell \~strike\~ \`code\`",
            "**Matched line (untrusted package-controlled evidence):**",
            "    <script>*untrusted*</script>\n    # injected heading",
            "    [old](https://old.example)",
            "    __new__",
        ):
            self.assertIn(text, packet)
        self.assertNotIn("\n# injected heading", packet)

    def test_packet_reports_each_attention_level(self) -> None:
        reviews = [
            PackageReview(
                AurUpdate(f"{severity.value.lower()}-pkg", "1.0-1", "1.1-1"),
                findings=[packet_finding(f"{severity.value.lower()}-rule", severity)],
            )
            for severity in Severity
        ]
        reviews.append(PackageReview(AurUpdate("none-pkg", "1.0-1", "1.1-1")))

        packet = format_review_packet(UpdateReviewResult(reviews))

        for review, attention in zip(reviews, ("HIGH", "MEDIUM", "LOW", "NONE"), strict=True):
            with self.subTest(package=review.update.package):
                section = packet.split(f"## Package: {review.update.package}", 1)[1]
                if review is not reviews[-1]:
                    next_package = reviews[reviews.index(review) + 1].update.package
                    section = section.split(f"## Package: {next_package}", 1)[0]
                self.assertIn(f"- **Attention:** {attention}", section)

    def test_incomplete_package_without_findings_remains_explicit(self) -> None:
        review = PackageReview(
            AurUpdate("broken-pkg", "3.0-1", "3.1-1"),
            notes=["Candidate metadata was not analyzed."],
            analysis_errors=["candidate metadata fetch failed: unavailable"],
        )

        packet = format_review_packet(UpdateReviewResult([review]))

        for text in (
            "- **Incomplete analyses:** 1",
            "- **Maximum severity:** NONE",
            "- **Analysis:** incomplete",
            "- **Attention:** NONE",
            "Candidate metadata was not analyzed.",
            "candidate metadata fetch failed: unavailable",
            "No configured patterns were detected in the available analysis for this package. "
            "Manual review is still required.",
            "None identified from findings.",
            "No rule-specific checklist items were generated.",
        ):
            self.assertIn(text, packet)

    def test_zero_update_packet_is_a_valid_document(self) -> None:
        self.assertEqual(
            format_review_packet(UpdateReviewResult([])),
            "\n".join(
                (
                    "# aur-diff-sentinel review packet",
                    "",
                    "> This packet is an aid for manual review, not a verdict that a package is safe or malicious.",
                    "",
                    "## Summary",
                    "",
                    "- **Updates:** 0",
                    "- **Packages with findings:** 0",
                    "- **Incomplete analyses:** 0",
                    "- **Maximum severity:** NONE",
                    "",
                    "## Packages",
                    "",
                    "No pending AUR updates were found.",
                    "",
                    "---",
                    "",
                    "No packages were updated.",
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()
