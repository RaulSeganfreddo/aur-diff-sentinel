from __future__ import annotations

import re

from aur_diff_sentinel.command_analysis import (
    is_direct_exec_package_manager,
    is_js_package_manager_command,
    uses_js_package_manager,
)
from aur_diff_sentinel.models import Rule, Severity, SourceLine
from aur_diff_sentinel.shell_analysis import (
    command_name,
    shell_commands,
    shell_pipelines,
    tokens_from_shell_segment,
)


SCRIPTLET_CONTEXTS = {"scriptlet", "hook"}
SENSITIVE_PATH_PREFIXES = ("/usr", "/etc", "/var", "/home", "/root")

HOOK_EXEC_RE = re.compile(r"^\s*Exec\s*=", re.IGNORECASE)

REDIRECT_TO_SENSITIVE_PATH_RE = re.compile(
    r"(>|>>)\s*['\"]?(/usr|/etc|/var|/home|/root)(/|\b)",
    re.IGNORECASE,
)


def _is_build_function(line: SourceLine) -> bool:
    return line.execution_context == "build"


def _network_in_build(line: SourceLine) -> bool:
    return _is_build_function(line) and any(
        _is_network_command(tokens) for tokens in shell_commands(line.content)
    )


def _is_network_command(tokens: list[str]) -> bool:
    command = command_name(tokens[0])
    args = [token.lower() for token in tokens[1:]]
    return (
        command in {"curl", "wget"}
        or (command == "git" and bool(args) and args[0] == "clone")
        or (re.fullmatch(r"pip[0-9.]*", command) is not None and bool(args) and args[0] == "install")
        or (command == "go" and bool(args) and args[0] == "get")
        or (command == "cargo" and bool(args) and args[0] == "install")
        or is_js_package_manager_command(tokens)
    )


def _curl_pipe_shell(line: SourceLine) -> bool:
    return _pipeline_match(line, lambda tokens: command_name(tokens[0]) in {"curl", "wget"})


def _decoded_pipe_shell(line: SourceLine) -> bool:
    return _pipeline_match(line, _is_decoder)


def _pipeline_match(line: SourceLine, producer) -> bool:
    for pipeline in shell_pipelines(line.content):
        for index, tokens in enumerate(pipeline[:-1]):
            if producer(tokens) and any(_is_shell(command) for command in pipeline[index + 1 :]):
                return True
    return False


def _is_shell(tokens: list[str]) -> bool:
    return command_name(tokens[0]) in {"sh", "bash"}


def _is_decoder(tokens: list[str]) -> bool:
    command = command_name(tokens[0])
    args = [token.lower() for token in tokens[1:]]
    return (
        (command == "base64" and bool({"-d", "--decode"} & set(args)))
        or (command == "xxd" and "-r" in args)
        or (command == "openssl" and "enc" in args and "-d" in args)
    )


def _setuid_permission(line: SourceLine) -> bool:
    return any(_command_sets_id_bits(tokens) for tokens in shell_commands(line.content))


def _command_sets_id_bits(tokens: list[str]) -> bool:
    command = command_name(tokens[0])
    if command == "chmod":
        return any(_is_setid_mode(token) for token in tokens[1:] if not token.startswith("--"))
    if command != "install":
        return False
    for index, token in enumerate(tokens[1:], start=1):
        if token in {"-m", "--mode"} and index + 1 < len(tokens):
            return _is_setid_mode(tokens[index + 1])
        mode_match = re.fullmatch(r"-[A-Za-z]*m([0-7]+)", token)
        if mode_match and _is_setid_mode(mode_match.group(1)):
            return True
        if token.startswith("--mode=") and _is_setid_mode(token.split("=", 1)[1]):
            return True
    return False


def _is_setid_mode(mode: str) -> bool:
    if re.fullmatch(r"[0-7]{3,5}", mode):
        return bool(int(mode, 8) & 0o6000)
    return re.fullmatch(r"[ugoa]*[ugoa]\+s", mode) is not None


def _scriptlet_package_manager(line: SourceLine) -> bool:
    return line.execution_context in SCRIPTLET_CONTEXTS and uses_js_package_manager(line.content)


def _direct_exec_package_manager(line: SourceLine) -> bool:
    return any(is_direct_exec_package_manager(tokens) for tokens in shell_commands(line.content))


def _pacman_hook_exec(line: SourceLine) -> bool:
    return line.execution_context == "hook" and HOOK_EXEC_RE.match(line.content) is not None


def _is_sensitive_path(token: str) -> bool:
    return any(
        token == prefix or token.startswith(f"{prefix}/")
        for prefix in SENSITIVE_PATH_PREFIXES
    )


def _tokens(line: str) -> list[str]:
    return tokens_from_shell_segment(line)


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
    Rule.contextual(
        id="curl-pipe-shell",
        severity=Severity.HIGH,
        matcher=_curl_pipe_shell,
        message="Remote download piped into a shell",
        hint="Executing downloaded content directly bypasses normal source review.",
    ),
    Rule.contextual(
        id="setuid-permission",
        severity=Severity.HIGH,
        matcher=_setuid_permission,
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
        pattern=r"^\s*install\s*=\s*['\"]?[^'\"\s#]+['\"]?",
        message="Install script referenced",
        hint="Install scripts can run during install, upgrade, and removal on the live system.",
    ),
    Rule.contextual(
        id="pacman-hook-exec",
        severity=Severity.MEDIUM,
        matcher=_pacman_hook_exec,
        message="Pacman hook action detected",
        hint="Pacman hooks can run automatically during package transactions.",
    ),
    Rule.regex(
        id="shell-c",
        severity=Severity.MEDIUM,
        pattern=r"(^\s*|[;&|]\s*)((/usr/bin/|/bin/)?(ba)?sh)\s+-c(\s|$)",
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
    Rule.contextual(
        id="decoded-pipe-shell",
        severity=Severity.HIGH,
        matcher=_decoded_pipe_shell,
        message="Decoded content piped into a shell",
        hint="Decoding content and executing it through a shell can hide behavior from review.",
    ),
    Rule.regex(
        id="inline-interpreter-command",
        severity=Severity.MEDIUM,
        pattern=r"(\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b|\bawk\b.*\bsystem\s*\()",
        message="Inline interpreter command detected",
        hint="Inline interpreter commands can hide meaningful behavior in compact code.",
    ),
    Rule.contextual(
        id="scriptlet-package-manager",
        severity=Severity.HIGH,
        matcher=_scriptlet_package_manager,
        message="Package manager command in install script or hook",
        hint="Package-manager commands in install scripts or pacman hooks run on the live system and can execute downloaded code.",
    ),
    Rule.contextual(
        id="direct-exec-package-manager",
        severity=Severity.HIGH,
        matcher=_direct_exec_package_manager,
        message="Package manager command may download and execute code",
        hint="Commands such as npx, bunx, and pnpm exec can fetch and execute code directly.",
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
