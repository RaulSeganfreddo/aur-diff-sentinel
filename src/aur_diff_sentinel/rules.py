from __future__ import annotations

import re
import shlex

from aur_diff_sentinel.models import Rule, Severity, SourceLine


BUILD_FUNCTIONS = {"prepare", "build", "check", "package"}
SENSITIVE_PATH_PREFIXES = ("/usr", "/etc", "/var", "/home", "/root")

NETWORK_IN_BUILD_RE = re.compile(
    r"(^\s*|[;&|]\s*)("
    r"curl(\s|$)|"
    r"wget(\s|$)|"
    r"git\s+clone(\s|$)|"
    r"npm\s+install(\s|$)|"
    r"pip[0-9.]*\s+install(\s|$)|"
    r"go\s+get(\s|$)|"
    r"cargo\s+install(\s|$)"
    r")",
    re.IGNORECASE,
)
REDIRECT_TO_SENSITIVE_PATH_RE = re.compile(
    r"(>|>>)\s*['\"]?(/usr|/etc|/var|/home|/root)(/|\b)",
    re.IGNORECASE,
)


def _is_build_function(line: SourceLine) -> bool:
    return line.function_name in BUILD_FUNCTIONS


def _network_in_build(line: SourceLine) -> bool:
    return _is_build_function(line) and NETWORK_IN_BUILD_RE.search(line.content) is not None


def _is_sensitive_path(token: str) -> bool:
    return any(
        token == prefix or token.startswith(f"{prefix}/")
        for prefix in SENSITIVE_PATH_PREFIXES
    )


def _tokens(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError:
        return line.split()


def _non_option_tokens(tokens: list[str]) -> list[str]:
    return [token for token in tokens if not token.startswith("-")]


def _writes_outside_pkgdir(line: SourceLine) -> bool:
    if not _is_build_function(line):
        return False

    if REDIRECT_TO_SENSITIVE_PATH_RE.search(line.content):
        return True

    tokens = _tokens(line.content)
    if not tokens:
        return False

    command = tokens[0]
    if command not in {"install", "cp", "mv", "mkdir", "touch", "chmod", "chown"}:
        return False

    if command in {"install", "cp", "mv"}:
        return len(tokens) > 1 and _is_sensitive_path(tokens[-1])

    operands = _non_option_tokens(tokens[1:])
    if command == "chmod" and len(operands) > 1:
        operands = operands[1:]
    if command == "chown" and len(operands) > 1:
        operands = operands[1:]

    return any(_is_sensitive_path(token) for token in operands)


def _source_command(line: SourceLine) -> bool:
    content = line.content.lstrip()
    if content.startswith("source"):
        rest = content[len("source"):]
        if not rest or not rest[0].isspace():
            return False
    elif content.startswith("."):
        rest = content[1:]
        if not rest or not rest[0].isspace():
            return False
    else:
        return False

    argument = rest.lstrip()
    return bool(argument) and not argument.startswith("#") and not argument.startswith("=")


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
    Rule.contextual(
        id="source-command",
        severity=Severity.MEDIUM,
        matcher=_source_command,
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
    Rule.contextual(
        id="network-in-build",
        severity=Severity.HIGH,
        matcher=_network_in_build,
        message="Network activity inside build function",
        hint="PKGBUILDs should normally declare downloaded inputs in source=().",
    ),
    Rule.contextual(
        id="writes-outside-pkgdir",
        severity=Severity.HIGH,
        matcher=_writes_outside_pkgdir,
        message="Command may write outside $pkgdir",
        hint="Package files should normally be staged under $pkgdir.",
    ),
]
