from __future__ import annotations

import re

from aur_diff_sentinel.models import Rule, Severity


RULES: list[Rule] = [
    Rule.regex(
        id="eval-used",
        severity=Severity.HIGH,
        pattern=r"(^\s*|[;&|]\s*)eval(\s|$)",
        message="Use of eval detected",
        hint="eval executes generated shell code and should be reviewed carefully.",
    ),
    Rule.regex(
        id="curl-pipe-shell",
        severity=Severity.HIGH,
        pattern=r"\b(curl|wget)\b[^|]*\|\s*(/usr/bin/)?(ba)?sh\b",
        message="Remote download piped into a shell",
        hint="Executing downloaded content directly bypasses normal source review.",
    ),
    Rule.regex(
        id="checksum-skip",
        severity=Severity.HIGH,
        pattern=r"\b(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_[a-z0-9_]+)?\b.*(['\"]?)SKIP\3",
        message="Checksum verification skipped",
        hint="SKIP can be legitimate for VCS sources, but should be reviewed.",
    ),
    Rule.regex(
        id="setuid-permission",
        severity=Severity.HIGH,
        pattern=r"\b(chmod\s+(?:[0-7]*[46][0-7]{3}|[ug]\+s)|install\s+-[A-Za-z]*m\s*?[46][0-7]{3}|install\s+-[A-Za-z]*m[46][0-7]{3})\b",
        message="Setuid or setgid permission detected",
        hint="Setuid/setgid files may execute with elevated privileges.",
    ),
    Rule.regex(
        id="privilege-command",
        severity=Severity.HIGH,
        pattern=r"(^\s*|[;&|]\s*)(sudo|doas|su\s+-|systemctl\s+(enable|start)|useradd|groupadd|passwd|crontab)(\s|$)",
        message="Command may modify users, services, or the live system",
        hint="PKGBUILDs should normally stage files under $pkgdir, not modify the live system.",
    ),
    Rule.regex(
        id="install-script",
        severity=Severity.MEDIUM,
        pattern=r"^\s*install\s*=\s*['\"]?[^'\"\s#]+\.install['\"]?",
        message="Install script referenced",
        hint=".install scripts can run during install, upgrade, and removal.",
    ),
    Rule.regex(
        id="shell-c",
        severity=Severity.MEDIUM,
        pattern=r"(^\s*|[;&|]\s*)((ba)?sh)\s+-c(\s|$)",
        message="Dynamic shell execution detected",
        hint="sh -c and bash -c can hide complex generated command execution.",
    ),
    Rule.regex(
        id="source-command",
        severity=Severity.MEDIUM,
        pattern=r"^\s*(source|\.)\s+[^\s#]+",
        message="Shell source command detected",
        hint="Sourcing a file executes it in the current shell context.",
    ),
    Rule.regex(
        id="obfuscated-command",
        severity=Severity.HIGH,
        pattern=r"(\bbase64\s+(-d|--decode)\b[^|;]*\|\s*(/usr/bin/)?(ba)?sh\b|\bxxd\s+-r\b|\bopenssl\s+enc\s+-d\b|\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b|\bawk\b.*\bsystem\s*\()",
        message="Obfuscated or compact dynamic execution detected",
        hint="Obfuscation or one-liner interpreters can hide behavior from review.",
    ),
]
