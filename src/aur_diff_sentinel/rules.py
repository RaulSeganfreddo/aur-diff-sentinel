from __future__ import annotations

import os
import re
import shlex

from aur_diff_sentinel.models import Rule, Severity, SourceLine


BUILD_FUNCTIONS = {"prepare", "build", "check", "package"}
SCRIPTLET_CONTEXTS = {"scriptlet", "hook"}
SENSITIVE_PATH_PREFIXES = ("/usr", "/etc", "/var", "/home", "/root")

ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
HOOK_EXEC_RE = re.compile(r"^\s*Exec\s*=", re.IGNORECASE)
EXEC_VALUE_RE = re.compile(r"^\s*Exec\s*=\s*(.*)$", re.IGNORECASE)

NETWORK_IN_BUILD_RE = re.compile(
    r"(^\s*|[;&|]\s*)("
    r"curl(\s|$)|"
    r"wget(\s|$)|"
    r"git\s+clone(\s|$)|"
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
    return line.execution_context == "build" or line.function_name in BUILD_FUNCTIONS


def _network_in_build(line: SourceLine) -> bool:
    return _is_build_function(line) and (
        NETWORK_IN_BUILD_RE.search(line.content) is not None
        or uses_js_package_manager(line.content)
    )


def uses_js_package_manager(content: str) -> bool:
    return any(is_js_package_manager_command(tokens) for tokens in shell_commands(content))


def changes_to_temp_dir(content: str) -> bool:
    return any(is_cd_to_temp_dir(tokens) for tokens in shell_commands(content))


def changes_to_non_temp_dir(content: str) -> bool:
    return any(is_cd_to_non_temp_dir(tokens) for tokens in shell_commands(content))


def _scriptlet_package_manager(line: SourceLine) -> bool:
    return line.execution_context in SCRIPTLET_CONTEXTS and uses_js_package_manager(line.content)


def _direct_exec_package_manager(line: SourceLine) -> bool:
    return any(is_direct_exec_package_manager(tokens) for tokens in shell_commands(line.content))


def _pacman_hook_exec(line: SourceLine) -> bool:
    return line.execution_context == "hook" and HOOK_EXEC_RE.match(line.content) is not None


def shell_commands(content: str, *, depth: int = 0) -> list[list[str]]:
    if depth > 2:
        return []

    content = _exec_value(content)
    commands: list[list[str]] = []
    for segment in _split_shell_segments(content):
        tokens = _tokens(segment)
        tokens = _strip_command_prefix(tokens)
        if not tokens:
            continue
        shell_payload = _shell_c_payload(tokens)
        if shell_payload is not None:
            commands.extend(shell_commands(shell_payload, depth=depth + 1))
            continue
        commands.append(tokens)
    return commands


def _exec_value(content: str) -> str:
    match = EXEC_VALUE_RE.match(content)
    if match:
        return match.group(1)
    return content


def _split_shell_segments(content: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escape = False
    index = 0

    while index < len(content):
        char = content[index]
        if escape:
            current.append(char)
            escape = False
            index += 1
            continue
        if char == "\\":
            current.append(char)
            escape = True
            index += 1
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            current.append(char)
            quote = char
            index += 1
            continue
        if content.startswith("&&", index) or content.startswith("||", index):
            _append_segment(segments, current)
            current = []
            index += 2
            continue
        if char in {";", "|"}:
            _append_segment(segments, current)
            current = []
            index += 1
            continue
        current.append(char)
        index += 1

    _append_segment(segments, current)
    return segments


def _append_segment(segments: list[str], chars: list[str]) -> None:
    segment = "".join(chars).strip()
    if segment:
        segments.append(segment)


def _strip_command_prefix(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens) and ASSIGNMENT_RE.match(tokens[index]):
        index += 1
    while index < len(tokens):
        command = _command_name(tokens[index])
        if command == "env":
            index = _strip_env_prefix(tokens, index + 1)
            continue
        if command == "command":
            index = _strip_command_builtin_prefix(tokens, index + 1)
            continue
        break
    return tokens[index:]


def _strip_env_prefix(tokens: list[str], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token in {"-i", "--ignore-environment", "-0", "--null"}:
            index += 1
            continue
        if token in {"-u", "--unset"}:
            index += 2
            continue
        if token.startswith("-u") and token != "-u":
            index += 1
            continue
        if token.startswith("--unset="):
            index += 1
            continue
        if ASSIGNMENT_RE.match(token):
            index += 1
            continue
        break
    return index


def _strip_command_builtin_prefix(tokens: list[str], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token in {"-p"}:
            index += 1
            continue
        break
    return index


def _shell_c_payload(tokens: list[str]) -> str | None:
    if _command_name(tokens[0]) not in {"sh", "bash"}:
        return None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "-c":
            if index + 1 < len(tokens):
                return tokens[index + 1]
            return None
        if token.startswith("-") and "c" in token[1:]:
            if index + 1 < len(tokens):
                return tokens[index + 1]
            return None
        index += 1
    return None


def _command_name(token: str) -> str:
    return os.path.basename(token).lower()


def is_js_package_manager_command(tokens: list[str]) -> bool:
    command = _command_name(tokens[0])
    args = [token.lower() for token in tokens[1:]]
    if command == "npm":
        return bool(args) and args[0] in {"install", "add", "ci", "i", "exec"}
    if command == "npx":
        return True
    if command == "bun":
        return bool(args) and args[0] in {"add", "install", "i"}
    if command == "bunx":
        return True
    if command == "yarn":
        return not args or args[0] in {"add", "install", "dlx"}
    if command == "pnpm":
        return bool(args) and args[0] in {"add", "install", "exec", "dlx"}
    return False


def is_direct_exec_package_manager(tokens: list[str]) -> bool:
    command = _command_name(tokens[0])
    args = [token.lower() for token in tokens[1:]]
    return (
        command in {"npx", "bunx"}
        or (command == "npm" and bool(args) and args[0] == "exec")
        or (command == "yarn" and bool(args) and args[0] == "dlx")
        or (command == "pnpm" and bool(args) and args[0] in {"exec", "dlx"})
    )


def is_cd_to_temp_dir(tokens: list[str]) -> bool:
    if _command_name(tokens[0]) != "cd" or len(tokens) < 2:
        return False
    return _is_temp_path(tokens[1])


def is_cd_to_non_temp_dir(tokens: list[str]) -> bool:
    if _command_name(tokens[0]) != "cd" or len(tokens) < 2:
        return False
    return not _is_temp_path(tokens[1])


def _is_temp_path(path: str) -> bool:
    normalized = path.rstrip("/")
    return normalized in {"/tmp", "/var/tmp"} or normalized.startswith("/tmp/") or normalized.startswith("/var/tmp/")


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
    Rule.regex(
        id="decoded-pipe-shell",
        severity=Severity.HIGH,
        pattern=r"\b(base64\s+(-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d)\b[^|;]*\|\s*(/usr/bin/)?(ba)?sh\b",
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
