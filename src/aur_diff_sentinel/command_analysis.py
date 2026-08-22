from __future__ import annotations

from aur_diff_sentinel.shell_analysis import command_name, shell_commands


def uses_js_package_manager(content: str) -> bool:
    return any(is_js_package_manager_command(tokens) for tokens in shell_commands(content))


def is_js_package_manager_command(tokens: list[str]) -> bool:
    command = command_name(tokens[0])
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
    command = command_name(tokens[0])
    args = [token.lower() for token in tokens[1:]]
    return (
        command in {"npx", "bunx"}
        or (command == "npm" and bool(args) and args[0] == "exec")
        or (command == "yarn" and bool(args) and args[0] == "dlx")
        or (command == "pnpm" and bool(args) and args[0] in {"exec", "dlx"})
    )


def is_cd_to_temp_dir(tokens: list[str]) -> bool:
    if command_name(tokens[0]) != "cd" or len(tokens) < 2:
        return False
    return _is_temp_path(tokens[1])


def is_cd_to_non_temp_dir(tokens: list[str]) -> bool:
    if command_name(tokens[0]) != "cd" or len(tokens) < 2:
        return False
    return not _is_temp_path(tokens[1])


def _is_temp_path(path: str) -> bool:
    normalized = path.rstrip("/")
    return normalized in {"/tmp", "/var/tmp"} or normalized.startswith("/tmp/") or normalized.startswith("/var/tmp/")
