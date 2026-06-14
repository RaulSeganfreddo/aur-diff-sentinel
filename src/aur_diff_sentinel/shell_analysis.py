from __future__ import annotations

import os
import re
import shlex


ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
EXEC_VALUE_RE = re.compile(r"^\s*Exec\s*=\s*(.*)$", re.IGNORECASE)


def shell_commands(content: str, *, depth: int = 0) -> list[list[str]]:
    if depth > 2:
        return []

    content = _exec_value(content)
    commands: list[list[str]] = []
    for segment in _split_shell_segments(content):
        tokens = tokens_from_shell_segment(segment)
        tokens = _strip_command_prefix(tokens)
        if not tokens:
            continue
        shell_payload = _shell_c_payload(tokens)
        if shell_payload is not None:
            commands.extend(shell_commands(shell_payload, depth=depth + 1))
            continue
        commands.append(tokens)
    return commands


def command_name(token: str) -> str:
    return os.path.basename(token).lower()


def tokens_from_shell_segment(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError:
        return line.split()


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
        command = command_name(tokens[index])
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
    if command_name(tokens[0]) not in {"sh", "bash"}:
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
