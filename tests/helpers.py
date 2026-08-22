from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Iterable
from pathlib import Path

from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.provider import AurUpdate
from aur_diff_sentinel.scanner import scan_text


SAMPLES = Path(__file__).parent / "samples"


class TempRootTestCase(unittest.TestCase):
    root: Path

    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))


def rule_ids(text: str) -> set[str]:
    return {finding.rule_id for finding in scan_text(text)}


def finding(
    rule_id: str,
    severity: Severity,
    *,
    old_value: str | None = None,
    new_value: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=rule_id.replace("-", " "),
        line_number=4,
        line_content="sha256sums=('SKIP')",
        hint="review this finding",
        filename="PKGBUILD",
        old_value=old_value,
        new_value=new_value,
    )


def fixture_fetcher(pkgver: str, pkgrel: str, extra_line: str):
    def fetcher(update: AurUpdate, target: Path) -> None:
        target.mkdir(parents=True)
        (target / "PKGBUILD").write_text(
            "\n".join(
                [
                    f"pkgname={update.package}",
                    f"pkgver={pkgver}",
                    f"pkgrel={pkgrel}",
                    extra_line,
                    "",
                ]
            ),
            encoding="utf-8",
        )

    return fetcher


def write_metadata(
    root: Path,
    pkgname: str,
    pkgver: str,
    pkgrel: str,
    *,
    epoch: str | None = None,
    checksum: str | None = "abc",
    extra_lines: Iterable[str] = (),
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    lines = [f"pkgname={pkgname}"]
    if epoch is not None:
        lines.append(f"epoch={epoch}")
    lines.extend((f"pkgver={pkgver}", f"pkgrel={pkgrel}"))
    if checksum is not None:
        lines.append(f"sha256sums=('{checksum}')")
    lines.extend(extra_lines)
    (root / "PKGBUILD").write_text(
        "\n".join((*lines, "")),
        encoding="utf-8",
    )
    if root.parent.name == "baselines":
        (root / ".aur-sentinel-baseline-version").write_text(
            f"{pkgver}-{pkgrel}",
            encoding="utf-8",
        )


def reviewed_cache(
    root: Path,
    *,
    package: str = "example-bin",
    old_pkgver: str = "1.0",
    new_pkgver: str = "1.1",
    checksum: str = "abc",
) -> tuple[AurUpdate, AurCache]:
    update = AurUpdate(package, f"{old_pkgver}-1", f"{new_pkgver}-1")
    cache = AurCache(root, fetcher=fixture_fetcher(new_pkgver, "1", f"sha256sums=('{checksum}')"))
    write_metadata(cache.baseline_dir(package), package, old_pkgver, "1")
    return update, cache


def write_cached_pair(
    cache: AurCache,
    package: str,
    baseline: tuple[str, str],
    latest: tuple[str, str],
) -> None:
    write_metadata(cache.baseline_dir(package), package, *baseline)
    write_metadata(cache.latest_dir(package), package, *latest)


def copy_repo_fetcher(source: Path):
    def fetcher(_update: AurUpdate, target: Path) -> None:
        shutil.copytree(source, target)

    return fetcher


def run_git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
