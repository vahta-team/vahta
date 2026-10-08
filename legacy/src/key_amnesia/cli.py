"""CLI entry point for key-amnesia / ka."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

from key_amnesia import __version__
from key_amnesia import crypto
from key_amnesia import dotenv_import
from key_amnesia import manifest as manifest_mod
from key_amnesia.audit import audit_event
from key_amnesia.config import (
    AUTH_EXEMPT_KEYS,
    ConfigError,
    load_config,
    set_config_value,
)
from key_amnesia.paths import vault_path
from key_amnesia.platform import describe_terminal
from key_amnesia.project import (
    VaultContext,
    ensure_project_scaffold,
    find_project_root,
    merge_secret_maps,
    merged_names_from_sidecars,
    project_vault_path,
    resolve_vault_context,
)
from key_amnesia.prompt_route import PromptRequest, require_human_auth
from key_amnesia.setup_cmd import cmd_setup
from key_amnesia import scan as scan_mod
from key_amnesia import theme
from key_amnesia.vault import (
    VaultError,
    empty_payload,
    load_vault,
    load_vault_with_key,
    names_path_for_vault,
    read_names,
    save_vault,
)

# Canonical human docs (GitHub wiki). Per-command --docs deferred until wiki IA
# is stable — one entry point avoids a rotting cmd→URL map.
DOCS_URL = "https://github.com/vahta-team/vahta/wiki"


def _write_command_output(stream: Any, text: str) -> None:
    """Relay a command's (already-scrubbed) output without crashing on a
    console codepage that can't represent one of its characters — the same
    degrade-don't-crash rule theme.py already applies to its own output."""
    try:
        stream.write(text)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "utf-8"
        stream.write(text.encode(encoding, errors="replace").decode(encoding, errors="replace"))


def _add_vault_scope_args(parser: argparse.ArgumentParser) -> None:
    """`--vault` / `--global` / `--no-global` / `--env` on vault-aware commands."""
    parser.add_argument(
        "--vault",
        default=None,
        metavar="PATH",
        help="Use this vault file directly (skips project discovery)",
    )
    g = parser.add_mutually_exclusive_group()
    g.add_argument(
        "--global",
        dest="force_global",
        action="store_true",
        help="Force the global ~/.key-amnesia vault (ignore project)",
    )
    g.add_argument(
        "--no-global",
        dest="no_global",
        action="store_true",
        help="Do not merge the global vault into a project unlock/run/list",
    )
    parser.add_argument(
        "--env",
        default=None,
        metavar="NAME",
        help="Project environment vault (.amnesia/envs/NAME/); also KA_ENV",
    )


def _ctx_from_args(args: argparse.Namespace) -> VaultContext:
    try:
        return resolve_vault_context(
            vault=getattr(args, "vault", None),
            force_global=bool(getattr(args, "force_global", False)),
            no_global=bool(getattr(args, "no_global", False)),
            env=getattr(args, "env", None),
        )
    except ValueError as e:
        theme.error(f"Error: {e}")
        raise SystemExit(2) from e


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="key-amnesia",
        description=(
            "Encrypted secret vault with human-prompt routing and output scrubbing. "
            "Windows and Linux supported; macOS isolated-console spawn is experimental."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    # init
    p_init = sub.add_parser(
        "init",
        help="Create an empty vault (double-confirm master password)",
    )
    p_init.add_argument(
        "--project",
        action="store_true",
        help="Create a project vault in ./.amnesia/ (auto-gitignores .amnesia/)",
    )
    p_init.add_argument(
        "--env",
        default=None,
        metavar="NAME",
        help="With --project: create .amnesia/envs/NAME/vault.bin",
    )

    # passwd / change-password
    p_passwd = sub.add_parser(
        "passwd",
        aliases=["change-password"],
        help="Change the master password (re-encrypts the vault with a fresh salt)",
    )
    _add_vault_scope_args(p_passwd)

    # set
    p_set = sub.add_parser("set", help="Store or update a secret (always fresh auth)")
    p_set.add_argument("name", help="Secret name")
    p_set.add_argument(
        "value",
        nargs="?",
        default=None,
        help="Secret value (prompted if omitted; never prefer argv for secrets)",
    )
    _add_vault_scope_args(p_set)

    # remove
    p_rm = sub.add_parser("remove", help="Remove a secret (always fresh auth)")
    p_rm.add_argument("name", help="Secret name")
    _add_vault_scope_args(p_rm)

    # import
    p_import = sub.add_parser(
        "import",
        help="Import secrets from dotenv file(s) into the vault (TTY-only)",
    )
    p_import.add_argument(
        "file",
        nargs="+",
        metavar="FILE",
        help="Path(s) to dotenv-format file(s), e.g. .env .env.local",
    )
    _add_vault_scope_args(p_import)

    # check (CI: project manifest vs project names sidecar — no decrypt)
    p_check = sub.add_parser(
        "check",
        help=(
            "Check amnesia.toml required secrets against the project names "
            "sidecar (no decrypt, no global vault; for CI)"
        ),
    )
    p_check.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human text",
    )
    _add_vault_scope_args(p_check)

    # scan (LEAK — Locally Exposed Agent Keys; advisory)
    p_scan = sub.add_parser(
        "scan",
        help=(
            "Scan for LEAK (Locally Exposed Agent Keys): plaintext secret "
            "files an agent can read (names/paths/counts only)"
        ),
    )
    p_scan.add_argument(
        "--deep",
        action="store_true",
        help=(
            "Also check home dotfiles, shell history, global git config, "
            "known MCP config paths, and agent session transcripts "
            "(Claude Code ~/.claude/projects/**/*.jsonl; Codex "
            "~/.codex/sessions|archived_sessions/**/rollout-*.jsonl; "
            "Copilot CLI ~/.copilot/session-state/*/events.jsonl). "
            "Not a full home walk. Detection is advisory "
            "(regex+entropy; false positives/negatives expected); "
            "never prints secret values."
        ),
    )
    p_scan.add_argument(
        "--include-excluded",
        "--wide",
        action="store_true",
        dest="include_excluded",
        help=(
            "Include default-excluded dirs (node_modules, .venv/venv, build "
            "dirs, .git internals). --wide is an alias. Git-history scanning "
            "is still out of scope. Independent of --deep."
        ),
    )
    p_scan.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human text",
    )
    p_scan.add_argument(
        "--strict",
        choices=("certain", "high", "paranoid"),
        default="high",
        help=(
            "Exit 1 when findings at this gate are present. "
            "certain: vendor prefixes and confirmed filenames only. "
            "high (default): certain + likely (assignments/UUID). "
            "paranoid: also possible (identifier/passphrase/low-transition; "
            "this is the 0.4.9-and-earlier assignment gate). Invalid value exits 2"
        ),
    )
    p_scan.add_argument(
        "--yes",
        action="store_true",
        help=(
            "After the report, import all importable dotenv findings into "
            "the project vault without selection prompts. Password still "
            "required from a TTY. Skips collisions, never deletes or "
            "renames source files, adds '.env*' to .gitignore when missing "
            "(gitignore is filesystem policy, not cryptographic). Still "
            "exits 1 while those source files remain"
        ),
    )
    p_scan.add_argument(
        "--no-import",
        action="store_true",
        help="Report only; never offer to store findings in the vault",
    )
    p_scan.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress --deep progress on stderr (stdout is unchanged)",
    )

    # run
    p_run = sub.add_parser(
        "run",
        help="Run a command with secrets injected into the environment",
    )
    p_run.add_argument(
        "--secret",
        action="append",
        default=[],
        metavar="NAME",
        help="Secret name to inject (repeatable)",
    )
    p_run.add_argument(
        "--as",
        dest="as_env",
        action="append",
        default=[],
        metavar="NAME=ENVVAR",
        help="Map secret NAME to environment variable ENVVAR",
    )
    p_run.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command to run (use -- before command)",
    )
    p_run.add_argument(
        "--cwd",
        default=None,
        metavar="DIR",
        help="Directory to run the command in (absolute path after resolve)",
    )
    p_run.add_argument(
        "--name",
        default=None,
        metavar="LABEL",
        help="Display-only client label shown in the guard's admission prompt",
    )
    _add_vault_scope_args(p_run)

    # list
    p_list = sub.add_parser("list", help="List secret names (no prompt; names sidecar)")
    p_list.add_argument(
        "--name",
        default=None,
        metavar="LABEL",
        help="Display-only client label shown in the guard's admission prompt",
    )
    _add_vault_scope_args(p_list)

    # unlock / lock
    p_unlock = sub.add_parser("unlock", help="Start cached guard session (requires password)")
    p_unlock.add_argument(
        "--pre-admit",
        action="store_true",
        help=(
            "Loudly pre-admit the very next client for a bounded window "
            "(default from config pre-admit-seconds) — no prompt for it"
        ),
    )
    p_unlock.add_argument(
        "--pre-admit-secret",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "Scope --pre-admit to this secret (repeatable); omit for an "
            "unscoped ALL-secrets pre-admit"
        ),
    )
    p_unlock.add_argument(
        "--admit-tree",
        action="store_true",
        help=(
            "Widen admission trust to descendants of a kernel-verified "
            "ancestor you choose at the first unrecognized-peer prompt"
        ),
    )
    _add_vault_scope_args(p_unlock)
    p_lock = sub.add_parser("lock", help="Tear down cached guard session")
    p_lock.add_argument(
        "--name",
        default=None,
        metavar="LABEL",
        help="Display-only client label shown in the guard's admission prompt",
    )
    _add_vault_scope_args(p_lock)

    # reveal / copy
    p_rev = sub.add_parser("reveal", help="Reveal a secret (always fresh auth)")
    p_rev.add_argument("name", help="Secret name")
    _add_vault_scope_args(p_rev)
    p_copy = sub.add_parser("copy", help="Copy a secret to clipboard (always fresh auth)")
    p_copy.add_argument("name", help="Secret name")
    _add_vault_scope_args(p_copy)

    # config
    p_cfg = sub.add_parser("config", help="View or set configuration")
    cfg_sub = p_cfg.add_subparsers(dest="config_command")
    cfg_sub.add_parser("show", help="Show current configuration")
    p_cfg_set = cfg_sub.add_parser(
        "set", help="Set a config value (always fresh auth)"
    )
    p_cfg_set.add_argument(
        "key",
        choices=[
            "session-mode",
            "session-timeout-minutes",
            "prompt-timeout-seconds",
            "pre-admit-seconds",
            "terminal",
        ],
    )
    p_cfg_set.add_argument(
        "value",
        help=(
            'For terminal: the command that runs something in it, flag '
            'included — "ghostty -e", "kitty", "wezterm start --" — or "auto" '
            "to detect one."
        ),
    )

    # status (connect is a plain alias — same handler, no separate verb)
    p_status = sub.add_parser("status", help="Show guard session status")
    p_status.add_argument(
        "--name",
        default=None,
        metavar="LABEL",
        help="Display-only client label shown in the guard's admission prompt",
    )
    _add_vault_scope_args(p_status)
    p_connect = sub.add_parser(
        "connect",
        help="Alias for 'status' (no separate guard verb — same status check)",
    )
    p_connect.add_argument(
        "--name",
        default=None,
        metavar="LABEL",
        help="Display-only client label shown in the guard's admission prompt",
    )
    _add_vault_scope_args(p_connect)

    # setup (agent distribution: skills + PreToolUse/preToolUse hook)
    p_setup = sub.add_parser(
        "setup",
        help="Install agent skills, the secret-guard hook, and harness allow-lists "
        "(Claude Code / Cursor / Codex / OpenCode)",
    )
    p_setup.add_argument(
        "--skills-only",
        action="store_true",
        help="Only install skills; skip merging the hook config",
    )
    p_setup.add_argument(
        "--hook-only",
        action="store_true",
        help="Only merge the hook config; skip installing skills",
    )
    p_setup.add_argument(
        "--permissions-only",
        action="store_true",
        help="Only merge harness allow-lists; skip skills and hook install",
    )
    p_setup.add_argument(
        "--permissions-remove",
        action="store_true",
        help="Remove previously recorded key-amnesia allow/deny rules",
    )
    p_setup.add_argument(
        "--terminal-only",
        action="store_true",
        help="Only choose the terminal used for password prompts (Linux)",
    )
    p_setup.add_argument(
        "--reconfigure-terminal",
        action="store_true",
        help="Ask again even if a terminal is already configured",
    )
    p_setup.add_argument(
        "--yes",
        action="store_true",
        help="Do not prompt before writing permission files (never deletes user allows)",
    )

    # docs — open/print wiki URL; no vault/guard/password
    p_docs = sub.add_parser(
        "docs",
        help="Print the documentation URL (and open it in a browser unless --print)",
    )
    p_docs.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="Print the URL only; do not try to open a browser",
    )

    # identity (local X25519 keypair for KAM2 membership)
    p_ident = sub.add_parser(
        "identity",
        help="Create or show the local keypair used for KAM2 membership",
    )
    ident_sub = p_ident.add_subparsers(dest="identity_command")
    p_ident_create = ident_sub.add_parser(
        "create", help="Generate a local identity (prints pubkey for ka member add)"
    )
    p_ident_create.add_argument(
        "--label", default="", help="Optional display label stored with the identity"
    )
    ident_sub.add_parser("show", help="Show local identity pubkey (never the private key)")

    # member (KAM2 roles — first add migrates KAM1->KAM2 with confirmed backup)
    p_member = sub.add_parser(
        "member",
        help="Manage vault members/roles (first add enables KAM2; confirmed migration)",
    )
    member_sub = p_member.add_subparsers(dest="member_command")
    p_member_add = member_sub.add_parser(
        "add", help="Add a member by pubkey (triggers KAM1->KAM2 on first enable)"
    )
    p_member_add.add_argument("name", help="Member display name")
    p_member_add.add_argument(
        "--pubkey", required=True, metavar="HEX", help="Member X25519 public key (hex)"
    )
    p_member_add.add_argument(
        "--role",
        required=True,
        choices=["admin", "writer", "runner"],
        help="admin / writer / runner",
    )
    p_member_add.add_argument(
        "--yes",
        action="store_true",
        help="Confirm KAM1->KAM2 upgrade without an interactive prompt",
    )
    _add_vault_scope_args(p_member_add)
    p_member_list = member_sub.add_parser("list", help="List members (names/roles/pubkeys)")
    _add_vault_scope_args(p_member_list)
    p_member_rm = member_sub.add_parser(
        "remove", help="Remove a member (warns to rotate secrets they could unwrap)"
    )
    p_member_rm.add_argument("name", help="Member display name")
    _add_vault_scope_args(p_member_rm)

    # grant / revoke (ACL)
    p_grant = sub.add_parser(
        "grant", help="Grant a secret to a member (KAM2 ACL; cryptographic wraps)"
    )
    p_grant.add_argument("secret", help="Secret name")
    p_grant.add_argument("--to", required=True, metavar="MEMBER", help="Member name")
    _add_vault_scope_args(p_grant)
    p_revoke = sub.add_parser("revoke", help="Revoke a secret from a member (KAM2 ACL)")
    p_revoke.add_argument("secret", help="Secret name")
    p_revoke.add_argument("--from", dest="member", required=True, metavar="MEMBER")
    _add_vault_scope_args(p_revoke)

    # export
    p_export = sub.add_parser(
        "export",
        help="Export ciphertext for one member (only their ACL'd secrets)",
    )
    p_export.add_argument(
        "--for",
        dest="member",
        required=True,
        metavar="MEMBER",
        help="Member name to export for",
    )
    p_export.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="PATH",
        help="Output path (default: <member>.kamx)",
    )
    _add_vault_scope_args(p_export)

    # internal helper (still supports --help; omitted from epilog summary)
    sub.add_parser("_prompt-helper", help=argparse.SUPPRESS)

    return parser


def _parse_as_mappings(as_env: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in as_env:
        if "=" not in item:
            raise SystemExit(f"Invalid --as mapping (expected NAME=ENVVAR): {item}")
        name, envvar = item.split("=", 1)
        if not name or not envvar:
            raise SystemExit(f"Invalid --as mapping: {item}")
        out[name] = envvar
    return out


def _prompt_new_master_password() -> str | None:
    """Prompt twice for a new master password; return it or None on failure."""
    p1 = getpass.getpass("Master password: ")
    p2 = getpass.getpass("Confirm master password: ")
    if not p1:
        theme.error("Error: master password cannot be empty.")
        return None
    if p1 != p2:
        theme.error(
            "Error: passwords do not match — vault not created.",
        )
        return None
    return p1


def _confirm(prompt: str, *, default: bool = False) -> bool:
    """Interactive yes/no prompt. Blank/EOF falls back to `default` rather
    than raising — but a default is always explicit in the prompt's own
    `[Y/n]` / `[y/N]` suffix, never a silently-assumed answer."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        answer = input(prompt + suffix).strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


def cmd_init(args: argparse.Namespace) -> int:
    project = bool(getattr(args, "project", False))
    env_name = getattr(args, "env", None)
    if env_name and not project:
        theme.error("Error: --env requires --project")
        return 2

    if project:
        project_root = Path.cwd()
        vp = ensure_project_scaffold(project_root, env_name=env_name, use_global=True)
    else:
        vp = vault_path()

    if vp.exists():
        theme.error(
            "vault already initialized, use ka set to add secrets",
        )
        return 1
    if not sys.stdin.isatty():
        theme.error(
            "Error: ka init requires an interactive terminal "
            "(run it directly in your console).",
        )
        return 1
    password = _prompt_new_master_password()
    if password is None:
        return 1
    try:
        save_vault(vp, password, empty_payload())
    except VaultError as e:
        theme.error(f"Error: {e}")
        return 1
    theme.success(f"Vault initialized at {vp}")
    if project:
        theme.info("Added .amnesia/ to .gitignore (if not already covered).")
        theme.info(
            "Project vault merges the global vault by default "
            "(use --no-global to isolate; set use_global in .amnesia/config.json)."
        )
    theme.info(
        "Remember your master password — it cannot be recovered if forgotten."
    )
    theme.info("Next: ka setup")
    return 0


def _auth_password(request: PromptRequest) -> tuple[bool, str | None, Any]:
    """Require human auth; return (ok, password_or_None, outcome).

    For inline: password is available.
    For spawned-console: password is None; outcome may carry run_result/status_only.
    """
    outcome = require_human_auth(request)
    if not outcome.ok:
        return False, None, outcome
    return True, outcome.password, outcome


def _check_role_policy(vault: Path, password: str, action: str) -> int | None:
    """Return an exit code if the local identity's role denies ``action``.

    Classification: **policy** vs a determined human with the master password;
    **effective** vs an agent using a runner identity. Returns None when allowed.
    """
    from key_amnesia import roles

    try:
        payload = load_vault(vault, password)
    except VaultError:
        return None  # caller will surface the vault error on its own path
    role = roles.role_for_identity(payload, roles.load_identity())
    if roles.policy_allows(action, role):
        return None
    assert role is not None
    theme.error(roles.deny_reason(action, role))
    audit_event(
        action,
        route="inline",
        result="denied",
        reason=f"role policy: {role}",
    )
    return 1


def _yes_no(prompt: str) -> bool:
    try:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def cmd_set(args: argparse.Namespace) -> int:
    ctx = _ctx_from_args(args)
    name = args.name
    value = args.value
    if not ctx.vault_path.exists():
        hint = "ka init --project" if ctx.project_root else "ka init"
        theme.error(f"Vault not initialized. Run '{hint}' first.")
        return 1
    # Prefer not putting secret values on argv — if omitted, prompt (inline only)
    # `mutation` (not `detail`!) carries the value — detail is human-facing
    # and printed at the auth prompt, mutation never is.
    request = PromptRequest(
        action="set",
        secret_names=[name],
        mutation=json.dumps({"name": name, "value": value}) if value is not None else "",
        vault_path=str(ctx.vault_path),
    )
    # If value missing and interactive, collect value after password inline.
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        # Inline path: perform mutation here.
        if value is None:
            value = getpass.getpass(f"Value for '{name}': ")
        try:
            payload = load_vault(ctx.vault_path, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            audit_event(
                "set",
                secret_names=[name],
                route=outcome.route,
                result="denied",
                reason=str(e),
            )
            return 1
        payload["secrets"][name] = value
        save_vault(ctx.vault_path, password, payload)
        audit_event(
            "set",
            secret_names=[name],
            route=outcome.route,
            result="allowed",
        )
        theme.success(f"Set secret '{name}'.")
        return 0

    # Spawned helper already mutated (or failed).
    if outcome.status_only and outcome.status_only.get("action") == "set":
        theme.success(f"Set secret '{name}'.")
        return 0
    # If value was None and we went non-interactive without detail, fail.
    if value is None:
        theme.error(
            "Non-interactive set requires the value (or an interactive terminal).",
        )
        return 1
    theme.error(f"Denied: {outcome.reason or 'set failed'}")
    return 1


def cmd_remove(args: argparse.Namespace) -> int:
    ctx = _ctx_from_args(args)
    name = args.name
    request = PromptRequest(
        action="remove",
        secret_names=[name],
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        try:
            payload = load_vault(ctx.vault_path, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            return 1
        if name not in payload["secrets"]:
            theme.error(f"Unknown secret: {name}")
            audit_event(
                "remove",
                secret_names=[name],
                route=outcome.route,
                result="denied",
                reason="unknown secret",
            )
            return 1
        del payload["secrets"][name]
        save_vault(ctx.vault_path, password, payload)
        audit_event(
            "remove", secret_names=[name], route=outcome.route, result="allowed"
        )
        theme.success(f"Removed secret '{name}'.")
        return 0

    if outcome.status_only and outcome.status_only.get("action") == "remove":
        theme.success(f"Removed secret '{name}'.")
        return 0
    theme.error(f"Denied: {outcome.reason or 'remove failed'}")
    return 1


def _emit_import_commit_result(result: dotenv_import.ImportCommitResult) -> None:
    """Print names and per-path outcomes only — never secret values."""
    if result.imported:
        theme.success(
            f"Imported {len(result.imported)} secret(s): {', '.join(result.imported)}"
        )
    if result.skipped:
        theme.info(f"Skipped (already in vault): {', '.join(result.skipped)}")
    if not result.imported and not result.skipped:
        theme.info("Nothing to import.")
    for raw_path, outcome in result.path_outcomes.items():
        src = Path(raw_path)
        if outcome == "deleted":
            theme.success(f"Deleted {src}.")
        elif outcome == "renamed":
            theme.success(f"Renamed {src} to {src.name}.imported.")
        elif outcome == "kept" and result.imported:
            theme.info(f"Left {src} in place.")
        elif outcome == "missing":
            theme.info(f"Skipped missing file: {src}")
    if result.gitignore_added:
        theme.success("Added '.env*' to .gitignore.")
    if result.manifest_path is not None:
        theme.info(f"Manifest updated: {result.manifest_path}")


def cmd_import(args: argparse.Namespace) -> int:
    """`ka import FILE [FILE ...]`: parse dotenv files and merge into the
    currently resolved vault.

    TTY-only, like `ka init` / `ka passwd` — this command reads local
    plaintext files directly (never an agent-supplied value) and drives
    several interactive decisions (collisions, delete/rename, .gitignore)
    that only make sense with a human at the keyboard, so it is never
    routed through the spawned-console agent-safe helper. Never prints a
    secret value at any point.
    """
    if not sys.stdin.isatty():
        theme.error(
            "Error: ka import requires an interactive terminal "
            "(run it directly in your console)."
        )
        return 1

    files = [Path(item) for item in args.file]
    for src in files:
        if not src.exists():
            theme.error(f"Error: file not found: {src}")
            return 1

    ctx = _ctx_from_args(args)
    vp = ctx.vault_path
    if not vp.exists():
        hint = "ka init --project" if ctx.project_root else "ka init"
        theme.error(f"Vault not initialized. Run '{hint}' first.")
        return 1

    any_entries = False
    for src in files:
        try:
            if dotenv_import.parse_dotenv(src):
                any_entries = True
                break
        except OSError as e:
            theme.error(f"Error reading {src}: {e}")
            return 1
    if not any_entries:
        if len(files) == 1:
            theme.info(f"No KEY=VALUE entries found in {files[0]}.")
        else:
            theme.info("No KEY=VALUE entries found.")
        return 0

    password = getpass.getpass("Master password: ")
    try:
        payload = load_vault(vp, password)
    except VaultError as e:
        theme.error(f"Error: {e}")
        audit_event("import", route="inline", result="denied", reason=str(e))
        return 1

    def _ask_collision(name: str) -> str:
        overwrite = _confirm(f"'{name}' already exists in the vault. Overwrite?")
        return "overwrite" if overwrite else "skip"

    root = ctx.project_root or Path.cwd()
    try:
        result = dotenv_import.commit_import(
            files,
            payload["secrets"],
            on_collision=_ask_collision,
            on_missing="error",
            commit_vault=lambda: save_vault(vp, password, payload),
            confirm_delete=lambda p: _confirm(
                f"Delete {p} now that its secrets are in the vault?"
            ),
            confirm_delete_again=lambda p: _confirm(
                f"This cannot be undone. Really delete {p}?"
            ),
            confirm_rename=lambda p: _confirm(
                f"Rename {p} to {p.name}.imported instead?", default=True
            ),
            gitignore_ask=lambda: _confirm(
                "Add '.env*' to .gitignore so these files are never committed?"
            ),
            project_root=root,
        )
    except VaultError as e:
        theme.error(f"Error: {e}")
        audit_event("import", route="inline", result="denied", reason=str(e))
        return 1
    except FileNotFoundError as e:
        theme.error(f"Error: file not found: {e}")
        return 1

    audit_event(
        "import",
        secret_names=result.imported,
        route="inline",
        result="allowed" if result.imported else "denied",
        reason="" if result.imported else "no new secrets (all skipped)",
    )
    _emit_import_commit_result(result)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """``ka check``: project ``amnesia.toml`` vs project names sidecar only.

    No decrypt, no global vault. Non-zero exit when required secrets are
    missing or the manifest is malformed. Designed for CI::

        ka check
        ka check --json
    """
    root = find_project_root()
    if root is None:
        msg = (
            "ka check requires a project vault (.amnesia/). "
            "Run 'ka init --project' first, or cd into the project."
        )
        if args.json:
            theme.out(
                json.dumps(
                    {
                        "ok": False,
                        "manifest": None,
                        "names_path": None,
                        "required": [],
                        "present": [],
                        "missing": [],
                        "optional_absent": [],
                        "error": msg,
                    },
                    indent=2,
                )
            )
        else:
            theme.error(msg)
        return 1

    # Resolve env the same way as other commands, but force no-global so the
    # names path is always the project sidecar.
    try:
        ctx = resolve_vault_context(
            env=getattr(args, "env", None),
            no_global=True,
            start=root,
        )
        names_path = (
            ctx.names_path
            if ctx.project_root is not None
            else names_path_for_vault(
                project_vault_path(root, getattr(args, "env", None))
            )
        )
    except ValueError as e:
        theme.error(f"Error: {e}")
        return 1

    result = manifest_mod.check_project(root, names_path=names_path)

    if args.json:
        theme.out(manifest_mod.format_check_json(result))
    else:
        text = manifest_mod.format_check_human(result)
        if result.ok:
            theme.out(text)
        else:
            theme.error(text)
    return 0 if result.ok else 1


def _scan_select_findings(
    importable: list[scan_mod.Finding],
    *,
    yes: bool,
) -> list[scan_mod.Finding]:
    """Pick which importable findings to store. ``--yes`` takes all.

    One prompt: numbered findings, then ``Selection [all]:``. Empty or
    ``all`` imports every listed finding; ``n`` / ``no`` imports none;
    comma-separated indices pick a subset.
    """
    if not importable:
        return []
    if yes:
        return list(importable)
    theme.out("")
    for i, f in enumerate(importable, start=1):
        names = ", ".join(f.secret_names)
        theme.out(f"  {i}. {f.path}  ({f.secret_count}: {names})")
    try:
        answer = input("Selection [all]: ").strip().lower()
    except EOFError:
        return []
    if not answer or answer == "all":
        return list(importable)
    if answer in ("n", "no"):
        return []
    chosen: list[scan_mod.Finding] = []
    for part in answer.split(","):
        part = part.strip()
        if not part.isdigit():
            continue
        idx = int(part)
        if 1 <= idx <= len(importable):
            chosen.append(importable[idx - 1])
    return chosen


def _scan_import_into_project(
    selected: list[scan_mod.Finding],
    project_root: Path,
    *,
    yes: bool,
) -> dict[str, str]:
    """Store selected dotenv findings into the project vault via dotenv_import.

    Creates ``.amnesia/`` if needed. Never prints secret values. Loads the
    project vault only (a ``use_global: true`` scaffold does not prompt for
    the global password here). With ``yes=True``, skip collisions, keep
    source files, and add ``.env*`` to ``.gitignore`` when missing
    (filesystem policy, not cryptographic).
    """
    if not selected:
        return {}

    vp = ensure_project_scaffold(project_root, use_global=True)
    if not vp.exists():
        if not sys.stdin.isatty():
            theme.error(
                "Error: project vault does not exist and cannot be created "
                "without an interactive terminal. Run 'ka init --project' first."
            )
            return {}
        theme.info(f"No project vault yet — creating {vp}")
        password = _prompt_new_master_password()
        if password is None:
            return {}
        try:
            save_vault(vp, password, empty_payload())
        except VaultError as e:
            theme.error(f"Error: {e}")
            return {}
        theme.success(f"Vault initialized at {vp}")
    else:
        if not sys.stdin.isatty():
            theme.error(
                "Error: importing scan findings requires an interactive "
                "terminal (master password)."
            )
            return {}
        password = getpass.getpass("Master password: ")

    try:
        payload = load_vault(vp, password)
    except VaultError as e:
        theme.error(f"Error: {e}")
        audit_event("scan_import", route="inline", result="denied", reason=str(e))
        return {}

    def _ask_collision(name: str) -> str:
        if yes:
            return "skip"
        overwrite = _confirm(f"'{name}' already exists in the vault. Overwrite?")
        return "overwrite" if overwrite else "skip"

    def _confirm_delete(path: Path) -> bool:
        if yes:
            return False
        return _confirm(f"Delete {path} now that its secrets are in the vault?")

    def _confirm_delete_again(path: Path) -> bool:
        if yes:
            return False
        return _confirm(f"This cannot be undone. Really delete {path}?")

    def _confirm_rename(path: Path) -> bool:
        if yes:
            return False
        return _confirm(
            f"Rename {path} to {path.name}.imported instead?", default=True
        )

    paths = [Path(f.path) for f in selected]
    try:
        result = dotenv_import.commit_import(
            paths,
            payload["secrets"],
            on_collision=_ask_collision,
            on_missing="skip",
            commit_vault=lambda: save_vault(vp, password, payload),
            confirm_delete=_confirm_delete,
            confirm_delete_again=_confirm_delete_again,
            confirm_rename=_confirm_rename,
            gitignore_ask=(
                (lambda: True)
                if yes
                else (
                    lambda: _confirm(
                        "Add '.env*' to .gitignore so these files are never committed?"
                    )
                )
            ),
            project_root=project_root,
        )
    except VaultError as e:
        theme.error(f"Error: {e}")
        audit_event("scan_import", route="inline", result="denied", reason=str(e))
        return {}

    if result.imported:
        audit_event(
            "scan_import",
            secret_names=result.imported,
            route="inline",
            result="allowed",
        )
    _emit_import_commit_result(result)
    return dict(result.path_outcomes)


def _scan_progress_printer() -> tuple[Any, Any]:
    """Stderr progress for ``ka scan --deep``. Never writes file contents."""
    last_len = 0
    try:
        tty = bool(sys.stderr.isatty())
    except Exception:
        tty = False

    def progress(stage: str, done: int, total: int) -> None:
        nonlocal last_len
        if total > 0:
            msg = f"{stage} {done}/{total}"
        else:
            msg = f"{stage} {done}"
        if tty:
            pad = max(0, last_len - len(msg))
            sys.stderr.write("\r" + msg + (" " * pad))
            sys.stderr.flush()
            last_len = len(msg)
        else:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()

    def finish() -> None:
        nonlocal last_len
        if tty and last_len:
            sys.stderr.write("\r" + (" " * last_len) + "\r")
            sys.stderr.flush()
            last_len = 0

    return progress, finish


def cmd_scan(args: argparse.Namespace) -> int:
    """``ka scan``: find LEAK (Locally Exposed Agent Keys) under cwd.

    Default exclusions skip ``node_modules``, ``.venv``/``venv``, common
    build dirs, and ``.git`` internals. ``--deep`` adds home/shell/MCP
    paths and known agent session transcript JSONL trees. Never prints
    secret values. Headline names the ``--strict`` gate; default
    ``--strict high`` counts certain + likely. ``--strict paranoid`` is
    the 0.4.9-and-earlier assignment gate. ``--wide`` aliases ``--include-excluded``.
    Optionally offers to store selected dotenv findings into the project
    vault via the shared ``dotenv_import`` core.
    """
    project_root = Path.cwd().resolve()
    findings = scan_mod.scan_project(
        project_root,
        include_excluded=bool(getattr(args, "include_excluded", False)),
    )
    progress = None
    finish_progress = None
    if getattr(args, "deep", False) and not bool(getattr(args, "quiet", False)):
        progress, finish_progress = _scan_progress_printer()
    try:
        if getattr(args, "deep", False):
            # Avoid double-counting files already seen under the project tree
            # when cwd is inside home.
            seen = {f.path for f in findings}
            for f in scan_mod.scan_deep(progress=progress):
                if f.path not in seen:
                    findings.append(f)
                    seen.add(f.path)
    finally:
        if finish_progress is not None:
            finish_progress()

    as_json = bool(getattr(args, "json", False))
    strict = getattr(args, "strict", "high") or "high"
    if as_json:
        theme.out(
            json.dumps(
                scan_mod.findings_to_json(
                    findings,
                    project_root=str(project_root),
                    strict=strict,
                ),
                indent=2,
            )
        )
    else:
        theme.out(
            scan_mod.format_human_report(
                findings,
                project_root=project_root,
                strict=strict,
            )
        )
        theme.out("")

    n = scan_mod.leak_count(findings, strict=strict)
    exit_code = 1 if n > 0 else 0

    # JSON / --no-import: report only. Interactive offer otherwise.
    if as_json or getattr(args, "no_import", False):
        return exit_code

    importable = scan_mod.importable_findings(findings)
    if not importable:
        return exit_code

    yes = bool(getattr(args, "yes", False))
    if yes and not sys.stdin.isatty():
        theme.error(
            "Error: --yes import still needs an interactive terminal "
            "for the master password. Re-run in your console, or use "
            "--no-import / --json for report-only."
        )
        return exit_code

    if not yes and not sys.stdin.isatty():
        # Non-TTY agents get the report + non-zero; no interactive offer.
        return exit_code

    selected = _scan_select_findings(importable, yes=yes)
    if selected:
        outcomes = _scan_import_into_project(selected, project_root, yes=yes)
        gone = {
            path
            for path, outcome in outcomes.items()
            if outcome in ("deleted", "renamed")
        }
        remaining = [
            f
            for f in findings
            if f.path not in gone and Path(f.path).exists()
        ]
        n = scan_mod.leak_count(remaining, strict=strict)
        exit_code = 1 if n > 0 else 0

    return exit_code


def _load_merged_secrets(
    ctx: VaultContext,
    password: str,
    *,
    prompt_global: bool = True,
) -> dict[str, str] | None:
    """Decrypt active vault; if merge enabled, prompt for a second (global) password.

    Returns merged secrets map, or None on error (already reported).
    """
    try:
        payload = load_vault(ctx.vault_path, password)
    except VaultError as e:
        theme.error(f"Error: {e}")
        return None
    secrets = {k: str(v) for k, v in payload.get("secrets", {}).items()}
    if not ctx.merge_with_global or ctx.global_vault_path is None:
        return secrets
    if not prompt_global:
        return secrets
    theme.info("Global vault also configured — enter its master password (separate).")
    global_pw = getpass.getpass("Global vault master password: ")
    try:
        g_payload = load_vault(ctx.global_vault_path, global_pw)
    except VaultError as e:
        theme.error(f"Error decrypting global vault: {e}")
        return None
    g_secrets = {k: str(v) for k, v in g_payload.get("secrets", {}).items()}
    return merge_secret_maps(g_secrets, secrets)


# Guard reply `code` values that must hard-stop `ka run` (no password fall-through).
_GUARD_RUN_HARD_STOP_CODES = frozenset(
    {
        "unknown_secret",
        "no_command",
        "invalid_message",
        "value_return_refused",
        "unknown_verb",
        "invalid_minutes",
    }
)


def cmd_run(args: argparse.Namespace) -> int:
    ctx = _ctx_from_args(args)
    cmd = list(args.cmd or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        theme.error("Usage: key-amnesia run --secret NAME [--as NAME=ENV] -- command...")
        return 2

    cwd_raw = getattr(args, "cwd", None)
    if cwd_raw:
        cwd_path = Path(cwd_raw).expanduser().resolve()
        if not cwd_path.is_dir():
            theme.error(f"Error: --cwd is not a directory: {cwd_raw}")
            return 2
        run_cwd = str(cwd_path)
    else:
        run_cwd = os.getcwd()

    inject_as = _parse_as_mappings(args.as_env)
    secret_names = list(args.secret or [])
    # Also include names only referenced in --as
    for n in inject_as:
        if n not in secret_names:
            secret_names.append(n)
    if not secret_names:
        theme.error("At least one --secret or --as is required.")
        return 2

    # Project manifest gate: fail before inject if required secrets are absent
    # from the injectable name set (sidecars only — no decrypt).
    if ctx.project_root is not None:
        mpath = manifest_mod.manifest_path_for(ctx.project_root)
        if mpath.exists():
            try:
                man = manifest_mod.load_manifest(mpath)
            except ValueError as e:
                theme.error(f"Error reading amnesia.toml: {e}")
                return 1
            if ctx.merge_with_global:
                present = set(merged_names_from_sidecars(ctx))
            else:
                present = set(read_names(ctx.names_path))
            pre = manifest_mod.check_against_names(
                man, present, names_path=ctx.names_path
            )
            if pre.missing:
                theme.error(manifest_mod.missing_required_message(pre.missing))
                return 1

    # Try live guard first (cached mode).
    from key_amnesia.guard import guard_is_alive, guard_request

    if guard_is_alive(path=ctx.lock_path):
        resp = guard_request(
            {
                "verb": "run",
                "secret_names": secret_names,
                "inject_as": inject_as,
                "command": cmd,
                "cwd": run_cwd,
            },
            timeout=3600,
            lock_path=ctx.lock_path,
        )
        if resp and resp.get("ok"):
            _write_command_output(sys.stdout, resp.get("scrubbed_stdout", ""))
            _write_command_output(sys.stderr, resp.get("scrubbed_stderr", ""))
            return int(resp.get("exit_code", 0))
        if resp is None:
            theme.warn(
                "Guard unreachable (IPC failed); falling back to per-call auth."
            )
        elif resp.get("expired") or resp.get("code") == "session_expired":
            theme.warn("Guard session expired; falling back to per-call auth.")
        elif not resp.get("ok"):
            code = str(resp.get("code") or "")
            reason = str(resp.get("reason") or "denied")
            if code in _GUARD_RUN_HARD_STOP_CODES:
                theme.error(f"Error: {reason}")
                return 1
            if code == "admission_denied":
                theme.warn(
                    "Guard admission denied; falling back to per-call auth. "
                    "Approve the next request on the unlock terminal, or use "
                    "`ka unlock --pre-admit`."
                )
            else:
                theme.warn(
                    f"Guard declined ({reason}); falling back to per-call auth."
                )
    request = PromptRequest(
        action="run",
        secret_names=secret_names,
        command=cmd,
        inject_as=inject_as,
        vault_path=str(ctx.vault_path),
        cwd=run_cwd,
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        from key_amnesia.run_exec import run_with_secrets

        secrets_map = _load_merged_secrets(ctx, password)
        if secrets_map is None:
            audit_event(
                "run",
                secret_names=secret_names,
                command=cmd,
                route=outcome.route,
                result="denied",
                reason="vault decrypt failed",
            )
            return 1
        missing = [n for n in secret_names if n not in secrets_map]
        if missing:
            theme.error(f"Unknown secrets: {', '.join(missing)}")
            return 1
        env_inject = {inject_as.get(n, n): secrets_map[n] for n in secret_names}
        by_name = {n: secrets_map[n] for n in secret_names}
        result = run_with_secrets(cmd, env_inject, by_name, cwd=run_cwd)
        audit_event(
            "run",
            secret_names=secret_names,
            command=cmd,
            route=outcome.route,
            result="allowed",
        )
        _write_command_output(sys.stdout, result.scrubbed_stdout)
        _write_command_output(sys.stderr, result.scrubbed_stderr)
        return result.exit_code

    # Helper already executed.
    if outcome.run_result:
        _write_command_output(sys.stdout, outcome.run_result.get("scrubbed_stdout", ""))
        _write_command_output(sys.stderr, outcome.run_result.get("scrubbed_stderr", ""))
        return int(outcome.run_result.get("exit_code") or 0)
    theme.error(f"Denied: {outcome.reason or 'run failed'}")
    return 1


def cmd_list(args: argparse.Namespace) -> int:
    ctx = _ctx_from_args(args)
    # Prefer live guard names if available; else sidecar (no prompt).
    from key_amnesia.guard import guard_is_alive, guard_request

    if guard_is_alive(path=ctx.lock_path):
        resp = guard_request({"verb": "list"}, lock_path=ctx.lock_path)
        if resp and resp.get("ok"):
            names = list(resp.get("names") or [])
            for n in names:
                theme.out(n)
            return 0
        if resp is None:
            theme.warn(
                "Guard unreachable (IPC failed); listing from vault sidecar names."
            )
        elif resp and not resp.get("ok"):
            theme.warn(
                f"Guard declined list ({resp.get('reason') or 'denied'}); "
                "listing from vault sidecar names."
            )
    if ctx.merge_with_global:
        names = merged_names_from_sidecars(ctx)
    else:
        names = read_names(ctx.names_path)
    for n in names:
        theme.out(n)
    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    """`ka unlock` *is* the guard: it decrypts, then blocks in this terminal.

    No detached child process, no bootstrap-env handoff. A non-interactive
    caller (agent-invoked) is routed the usual way — inline vs. spawned
    console — but a spawned helper console refuses the unlock action itself
    (a separate console can't become this terminal's foreground guard).
    """
    from key_amnesia.guard import VaultSource, guard_is_alive, run_foreground_guard

    ctx = _ctx_from_args(args)

    if guard_is_alive(path=ctx.lock_path):
        theme.warn("Guard session already active.")
        return 0

    if not ctx.vault_path.exists():
        hint = "ka init --project" if ctx.project_root else "ka init"
        theme.error(f"Vault not initialized. Run '{hint}' first.")
        return 1

    cfg = load_config()
    timeout_min = int(cfg.get("session-timeout-minutes", 30))
    pre_admit = bool(getattr(args, "pre_admit", False))
    pre_admit_secrets = list(getattr(args, "pre_admit_secret", None) or [])
    pre_admit_seconds = int(cfg.get("pre-admit-seconds", 900))
    admit_tree = bool(getattr(args, "admit_tree", False))
    detail = f"session timeout: {timeout_min} minutes"
    if pre_admit:
        scope = ", ".join(pre_admit_secrets) if pre_admit_secrets else "ALL secrets"
        detail += f"; --pre-admit armed for {scope} ({pre_admit_seconds}s window)"
    if admit_tree:
        detail += "; --admit-tree (choose ancestor as admission root)"
    request = PromptRequest(
        action="unlock",
        detail=detail,
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        try:
            payload, vkey = load_vault_with_key(ctx.vault_path, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            audit_event(
                "unlock", route=outcome.route, result="denied", reason=str(e)
            )
            return 1

        sources: list[VaultSource] | None = None
        if ctx.merge_with_global and ctx.global_vault_path is not None:
            theme.info(
                "Global vault also configured — enter its master password (separate)."
            )
            global_pw = getpass.getpass("Global vault master password: ")
            try:
                g_payload, g_key = load_vault_with_key(
                    ctx.global_vault_path, global_pw
                )
            except VaultError as e:
                theme.error(f"Error decrypting global vault: {e}")
                audit_event(
                    "unlock", route=outcome.route, result="denied", reason=str(e)
                )
                return 1
            sources = [
                VaultSource(path=ctx.global_vault_path, key=g_key),
                VaultSource(path=ctx.vault_path, key=vkey),
            ]
            merged = merge_secret_maps(
                {k: str(v) for k, v in g_payload.get("secrets", {}).items()},
                {k: str(v) for k, v in payload.get("secrets", {}).items()},
            )
            payload = dict(payload)
            payload["secrets"] = merged

        audit_event("unlock", route=outcome.route, result="allowed")
        # Retain only the derived key (never the password) so the guard can
        # reload the vault on a content change without a fresh Argon2id run
        # or a second password prompt — see guard._maybe_reload_secrets.
        return run_foreground_guard(
            payload,
            timeout_min,
            vault_path=ctx.vault_path,
            vault_key=vkey,
            vault_sources=sources,
            lock_path=ctx.lock_path,
            last_guard_state_path=ctx.last_guard_state_path,
            project_root=str(ctx.project_root) if ctx.project_root else None,
            env_name=ctx.env_name,
            pre_admit=pre_admit,
            pre_admit_secrets=pre_admit_secrets,
            pre_admit_seconds=pre_admit_seconds,
            admit_tree=admit_tree,
        )

    theme.error(f"Denied: {outcome.reason or 'unlock failed'}")
    return 1


def cmd_lock(args: argparse.Namespace) -> int:
    from key_amnesia.guard import (
        clear_guard_lock,
        format_no_guard_message,
        guard_is_alive,
        guard_request,
    )

    ctx = _ctx_from_args(args)

    if not guard_is_alive(path=ctx.lock_path):
        clear_guard_lock(path=ctx.lock_path)
        theme.info(format_no_guard_message(path=ctx.last_guard_state_path))
        return 0
    resp = guard_request({"verb": "lock"}, lock_path=ctx.lock_path)
    clear_guard_lock(path=ctx.lock_path)
    if resp and resp.get("ok"):
        theme.success("Locked.")
        return 0
    theme.info("Lock signal sent; cleared local lock file.")
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    # Always fresh auth — never guard shortcut. Single vault (no merge).
    ctx = _ctx_from_args(args)
    name = args.name
    request = PromptRequest(
        action="reveal",
        secret_names=[name],
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        denied = _check_role_policy(ctx.vault_path, password, "reveal")
        if denied is not None:
            return denied
        try:
            payload = load_vault(ctx.vault_path, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            return 1
        secrets_map = payload.get("secrets", {})
        if name not in secrets_map:
            theme.error(f"Unknown secret: {name}")
            return 1
        # Raw secret value — never themed.
        sys.stdout.write(f"{secrets_map[name]}\n")
        audit_event(
            "reveal", secret_names=[name], route=outcome.route, result="allowed"
        )
        return 0

    # Non-interactive: helper showed in its window; caller gets status only.
    if outcome.status_only and outcome.status_only.get("shown"):
        theme.info(f"Secret '{name}' displayed in authentication console.")
        return 0
    theme.error(f"Denied: {outcome.reason or 'reveal failed'}")
    return 1


def cmd_copy(args: argparse.Namespace) -> int:
    ctx = _ctx_from_args(args)
    name = args.name
    request = PromptRequest(
        action="copy",
        secret_names=[name],
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        denied = _check_role_policy(ctx.vault_path, password, "copy")
        if denied is not None:
            return denied
        from key_amnesia.clipboard import copy_to_clipboard

        try:
            payload = load_vault(ctx.vault_path, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            return 1
        secrets_map = payload.get("secrets", {})
        if name not in secrets_map:
            theme.error(f"Unknown secret: {name}")
            return 1
        copy_to_clipboard(str(secrets_map[name]))
        audit_event(
            "copy", secret_names=[name], route=outcome.route, result="allowed"
        )
        theme.success(f"Copied '{name}' to clipboard.")
        return 0

    if outcome.status_only and outcome.status_only.get("copied"):
        theme.info(f"Secret '{name}' copied in authentication console.")
        return 0
    theme.error(f"Denied: {outcome.reason or 'copy failed'}")
    return 1


def cmd_config(args: argparse.Namespace) -> int:
    if args.config_command == "show" or args.config_command is None:
        cfg = load_config()
        theme.out(json.dumps(cfg, indent=2))
        return 0
    if args.config_command == "set":
        if args.key in AUTH_EXEMPT_KEYS:
            # See config.AUTH_EXEMPT_KEYS: `terminal` decides where a password
            # can be typed, so it cannot be gated behind typing one. Agents are
            # still blocked from `config set` by ka_policy, not by this check.
            try:
                set_config_value(args.key, args.value)
            except ConfigError as e:
                theme.error(f"Error: {e}")
                return 1
            stored = load_config().get(args.key)
            audit_event("config", route="inline", result="allowed", reason=f"set {args.key}")
            theme.success(f"Set {args.key} = {stored if stored else '(auto-detect)'}")
            return 0
        request = PromptRequest(
            action="config",
            detail=f"config key: {args.key}",
            mutation=json.dumps({"key": args.key, "value": args.value}),
        )
        ok, password, outcome = _auth_password(request)
        if not ok:
            theme.error(f"Denied: {outcome.reason}")
            return 1
        if password is not None:
            # Verify password against vault if it exists (fresh auth proof).
            vp = vault_path()
            if vp.exists():
                try:
                    load_vault(None, password)
                except VaultError as e:
                    theme.error(f"Error: {e}")
                    return 1
            try:
                set_config_value(args.key, args.value)
            except ConfigError as e:
                theme.error(f"Error: {e}")
                return 1
            audit_event(
                "config",
                route=outcome.route,
                result="allowed",
                reason=f"set {args.key}",
            )
            theme.success(f"Set {args.key} = {args.value}")
            return 0
        if outcome.status_only and outcome.status_only.get("action") == "config":
            theme.success(f"Set {args.key} = {args.value}")
            return 0
        theme.error(f"Denied: {outcome.reason or 'config failed'}")
        return 1
    theme.error("Usage: key-amnesia config [show|set KEY VALUE]")
    return 2


def _format_remaining(expires_at_epoch: Any) -> str | None:
    """Human-readable countdown to a guard's expiry, or None if unknown/past."""
    try:
        remaining = float(expires_at_epoch) - time.time()
    except (TypeError, ValueError):
        return None
    if remaining <= 0:
        return "expiring now"
    minutes, seconds = divmod(int(remaining), 60)
    return f"{minutes}m {seconds}s"


def cmd_status(args: argparse.Namespace) -> int:
    from key_amnesia.guard import (
        format_no_guard_message,
        guard_is_alive,
        guard_request,
        list_guard_registry_entries,
        read_guard_lock,
    )

    ctx = _ctx_from_args(args)

    lock = read_guard_lock(path=ctx.lock_path)
    if not lock or not guard_is_alive(lock, path=ctx.lock_path):
        theme.out("guard: inactive")
        theme.out(format_no_guard_message(path=ctx.last_guard_state_path))
        cfg = load_config()
        theme.out(f"session-mode: {cfg.get('session-mode')}")
        theme.out(f"terminal: {describe_terminal()}")
        if ctx.project_root:
            theme.out(f"project: {ctx.project_root}")
            theme.out(f"vault: {ctx.vault_path}")
            theme.out(f"merge_global: {'yes' if ctx.merge_with_global else 'no'}")
        others = list_guard_registry_entries()
        for entry in others:
            theme.out(
                f"other_guard: pid={entry.get('pid')} vault={entry.get('vault_path')}"
            )
        return 0
    resp = guard_request({"verb": "status"}, lock_path=ctx.lock_path)
    theme.out("guard: active")
    if ctx.project_root:
        theme.out(f"project: {ctx.project_root}")
        theme.out(f"vault: {ctx.vault_path}")
        theme.out(f"merge_global: {'yes' if ctx.merge_with_global else 'no'}")
    if resp and resp.get("ok"):
        theme.out(f"pid: {resp.get('pid')}")
        theme.out(f"expires_at: {resp.get('expires_at')}")
        remaining = _format_remaining(resp.get("expires_at_epoch"))
        if remaining:
            theme.out(f"remaining: {remaining}")
        theme.out(f"secret_count: {resp.get('secret_count')}")
        theme.out(f"admitted: {'yes' if resp.get('admitted') else 'no'}")
        if resp.get("admitted_since"):
            theme.out(f"admitted_since: {resp.get('admitted_since')}")
        if resp.get("admitted_pids"):
            theme.out(f"admitted_pids: {resp.get('admitted_pids')}")
        if resp.get("granted_secrets"):
            theme.out(f"granted_secrets: {resp.get('granted_secrets')}")
        if resp.get("granted_until"):
            theme.out(f"granted_until: {resp.get('granted_until')}")
        if resp.get("pre_admit_pending"):
            theme.out(f"pre_admit_pending: yes (scope: {resp.get('pre_admit_scope')})")
            theme.out(f"pre_admit_until: {resp.get('pre_admit_until')}")
        theme.out(f"request_count: {resp.get('request_count', 0)}")
    else:
        theme.out(f"pid: {lock.get('pid')}")
        theme.out(f"expires_at: {lock.get('expires_at')}")
        remaining = _format_remaining(lock.get("expires_at_epoch"))
        if remaining:
            theme.out(f"remaining: {remaining}")
    others = [
        e
        for e in list_guard_registry_entries()
        if Path(str(e.get("vault_path") or "")).resolve() != ctx.vault_path.resolve()
    ]
    for entry in others:
        theme.out(
            f"other_guard: pid={entry.get('pid')} vault={entry.get('vault_path')}"
        )
    return 0


def cmd_passwd(args: argparse.Namespace) -> int:
    """Change the master password: re-encrypts the vault with a fresh salt.

    Refuses outright while a guard session is alive (the guard holds the
    old-password-derived key in memory and would go stale mid-session), and
    is TTY-only like `ka init` — never routed through the spawned-console
    helper, since the master password can never leave this process either
    way.
    """
    from key_amnesia.guard import guard_is_alive

    ctx = _ctx_from_args(args)

    if guard_is_alive(path=ctx.lock_path):
        theme.error("Lock the vault first: ka lock")
        return 1

    vp = ctx.vault_path
    if not vp.exists():
        theme.error("Vault not initialized. Run 'ka init' first.")
        return 1
    if not sys.stdin.isatty():
        theme.error(
            "Error: ka passwd requires an interactive terminal "
            "(run it directly in your console)."
        )
        return 1

    current_password = getpass.getpass("Current master password: ")
    try:
        payload = load_vault(vp, current_password)
    except VaultError as e:
        theme.error(f"Error: {e}")
        audit_event("passwd", route="inline", result="denied", reason=str(e))
        return 1

    new_password = _prompt_new_master_password()
    if new_password is None:
        audit_event(
            "passwd", route="inline", result="denied", reason="new password rejected"
        )
        return 1

    save_vault(vp, new_password, payload, salt=crypto.generate_salt())
    audit_event("passwd", route="inline", result="allowed")
    theme.success("Master password changed.")
    return 0


def cmd_docs(args: argparse.Namespace) -> int:
    """Print the wiki URL; optionally open a browser. Never touches the vault.

    Always exits 0 — a missing browser or failed open must not fail the command.
    Per-command ``--docs`` flags are deferred; this is the single entry point.
    """
    # Plain print so agents and scripts can capture the URL without theme codes.
    print(DOCS_URL)
    if getattr(args, "print_only", False):
        return 0
    try:
        webbrowser.open(DOCS_URL)
    except Exception:
        pass
    return 0


def cmd_identity(args: argparse.Namespace) -> int:
    from key_amnesia import roles

    sub = getattr(args, "identity_command", None)
    if sub == "create":
        existing = roles.load_identity()
        if existing is not None:
            theme.error(
                "Identity already exists. Remove identity.json manually to rotate "
                f"(pubkey={existing.get('box_pk')})."
            )
            return 1
        record = roles.create_identity(label=getattr(args, "label", "") or "")
        theme.success("Local identity created.")
        theme.out(f"pubkey: {record['box_pk']}")
        theme.info("Give this pubkey to a vault admin: ka member add NAME --pubkey ... --role ...")
        return 0
    if sub == "show" or sub is None:
        record = roles.load_identity()
        if record is None:
            theme.info("No local identity. Run: ka identity create")
            return 1
        theme.out(f"label: {record.get('label') or '(none)'}")
        theme.out(f"pubkey: {record['box_pk']}")
        theme.out(f"created_at: {record.get('created_at', '')}")
        return 0
    theme.error("Usage: ka identity [create|show]")
    return 2


def cmd_member(args: argparse.Namespace) -> int:
    from key_amnesia import roles

    sub = getattr(args, "member_command", None)
    if sub == "list":
        return _cmd_member_list(args)
    if sub == "add":
        return _cmd_member_add(args)
    if sub == "remove":
        return _cmd_member_remove(args)
    theme.error("Usage: ka member [add|list|remove]")
    return 2


def _cmd_member_list(args: argparse.Namespace) -> int:
    from key_amnesia import roles
    from key_amnesia.vault import detect_vault_magic, MAGIC_KAM2

    ctx = _ctx_from_args(args)
    if not ctx.vault_path.exists():
        theme.error("Vault not initialized. Run 'ka init' first.")
        return 1
    if detect_vault_magic(ctx.vault_path) != MAGIC_KAM2:
        theme.info("Vault is KAM1 (roles not enabled). Add a member to upgrade.")
        return 0

    request = PromptRequest(
        action="member_list",
        detail="list members",
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1
    if password is None:
        theme.error("member list requires inline auth")
        return 1
    try:
        payload = load_vault(ctx.vault_path, password)
    except VaultError as e:
        theme.error(f"Error: {e}")
        return 1
    members = (payload.get("kam2") or {}).get("members") or {}
    if not members:
        theme.info("No members.")
        return 0
    for mid, info in sorted(members.items(), key=lambda kv: kv[1].get("name", "")):
        theme.out(
            f"{info.get('name')}  role={info.get('role')}  pubkey={info.get('box_pk')}"
        )
    if not roles.verify_acl_signature(payload):
        theme.warn(
            "ACL signature verification FAILED (tamper-evident warning — "
            "cryptographic detection only)."
        )
    return 0


def _cmd_member_add(args: argparse.Namespace) -> int:
    from key_amnesia import roles
    from key_amnesia.vault import MAGIC_KAM1, MAGIC_KAM2, detect_vault_magic

    if not sys.stdin.isatty() and not getattr(args, "yes", False):
        theme.error(
            "Error: ka member add requires an interactive terminal "
            "(or --yes to confirm a KAM1->KAM2 upgrade)."
        )
        return 1

    ctx = _ctx_from_args(args)
    if not ctx.vault_path.exists():
        theme.error("Vault not initialized. Run 'ka init' first.")
        return 1

    request = PromptRequest(
        action="member_add",
        detail=f"add member {args.name} role={args.role}",
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1
    if password is None:
        theme.error("member add requires inline auth")
        return 1

    denied = _check_role_policy(ctx.vault_path, password, "member_add")
    if denied is not None:
        return denied

    magic = detect_vault_magic(ctx.vault_path)
    try:
        if magic == MAGIC_KAM1:
            def _confirm(msg: str) -> bool:
                if getattr(args, "yes", False):
                    return True
                theme.warn(msg)
                return _yes_no("Type yes to upgrade")

            def _announce(msg: str) -> None:
                theme.warn(msg)

            payload = roles.migrate_kam1_to_kam2(
                ctx.vault_path,
                password,
                confirm=_confirm,
                announce=_announce,
            )
            theme.success(
                f"Upgraded to KAM2. Backup: {roles.kam1_backup_path(ctx.vault_path)}"
            )
        elif magic == MAGIC_KAM2:
            payload = load_vault(ctx.vault_path, password)
        else:
            theme.error("Unrecognized vault format")
            return 1

        roles.add_member(
            payload,
            name=args.name,
            box_pk_hex=args.pubkey,
            role=args.role,
        )
        save_vault(ctx.vault_path, password, payload)
    except roles.RolesError as e:
        theme.error(f"Error: {e}")
        return 1
    except VaultError as e:
        theme.error(f"Error: {e}")
        return 1

    audit_event(
        "member_add",
        route=outcome.route,
        result="allowed",
        reason=f"{args.name}:{args.role}",
    )
    theme.success(f"Added member '{args.name}' with role '{args.role}'.")
    theme.info(
        "Grant secrets with: ka grant SECRET --to "
        f"{args.name}  (cryptographic wraps; runner reveal/copy is policy-only)"
    )
    return 0


def _cmd_member_remove(args: argparse.Namespace) -> int:
    from key_amnesia import roles

    ctx = _ctx_from_args(args)
    request = PromptRequest(
        action="member_remove",
        detail=f"remove member {args.name}",
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1
    if password is None:
        theme.error("member remove requires inline auth")
        return 1
    denied = _check_role_policy(ctx.vault_path, password, "member_remove")
    if denied is not None:
        return denied
    try:
        payload = load_vault(ctx.vault_path, password)
        payload, warning = roles.remove_member(payload, args.name)
        save_vault(ctx.vault_path, password, payload)
    except (roles.RolesError, VaultError) as e:
        theme.error(f"Error: {e}")
        return 1
    audit_event(
        "member_remove", route=outcome.route, result="allowed", reason=args.name
    )
    theme.success(f"Removed member '{args.name}'.")
    theme.warn(warning)
    return 0


def cmd_grant(args: argparse.Namespace) -> int:
    from key_amnesia import roles

    ctx = _ctx_from_args(args)
    request = PromptRequest(
        action="grant",
        secret_names=[args.secret],
        detail=f"grant {args.secret} to {args.to}",
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1
    if password is None:
        theme.error("grant requires inline auth")
        return 1
    denied = _check_role_policy(ctx.vault_path, password, "grant")
    if denied is not None:
        return denied
    try:
        payload = load_vault(ctx.vault_path, password)
        roles.grant_secret(payload, args.secret, args.to)
        save_vault(ctx.vault_path, password, payload)
    except (roles.RolesError, VaultError) as e:
        theme.error(f"Error: {e}")
        return 1
    audit_event(
        "grant",
        secret_names=[args.secret],
        route=outcome.route,
        result="allowed",
        reason=f"to={args.to}",
    )
    theme.success(f"Granted '{args.secret}' to '{args.to}' (cryptographic wrap).")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    from key_amnesia import roles

    ctx = _ctx_from_args(args)
    request = PromptRequest(
        action="revoke",
        secret_names=[args.secret],
        detail=f"revoke {args.secret} from {args.member}",
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1
    if password is None:
        theme.error("revoke requires inline auth")
        return 1
    denied = _check_role_policy(ctx.vault_path, password, "revoke")
    if denied is not None:
        return denied
    try:
        payload = load_vault(ctx.vault_path, password)
        roles.revoke_secret(payload, args.secret, args.member)
        save_vault(ctx.vault_path, password, payload)
    except (roles.RolesError, VaultError) as e:
        theme.error(f"Error: {e}")
        return 1
    audit_event(
        "revoke",
        secret_names=[args.secret],
        route=outcome.route,
        result="allowed",
        reason=f"from={args.member}",
    )
    theme.success(f"Revoked '{args.secret}' from '{args.member}'.")
    theme.warn("Rotate the secret if the member may have exported it earlier.")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from key_amnesia import roles

    ctx = _ctx_from_args(args)
    request = PromptRequest(
        action="export",
        detail=f"export for {args.member}",
        vault_path=str(ctx.vault_path),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1
    if password is None:
        theme.error("export requires inline auth")
        return 1
    denied = _check_role_policy(ctx.vault_path, password, "export")
    if denied is not None:
        return denied
    try:
        payload = load_vault(ctx.vault_path, password)
        blob = roles.build_export_blob(payload, args.member)
    except (roles.RolesError, VaultError) as e:
        theme.error(f"Error: {e}")
        return 1
    out_path = Path(args.output) if args.output else Path(f"{args.member}.kamx")
    out_path.write_bytes(blob)
    audit_event(
        "export",
        route=outcome.route,
        result="allowed",
        reason=f"for={args.member}",
    )
    theme.success(
        f"Wrote export for '{args.member}' to {out_path} "
        f"(ciphertext only — cryptographic SealedBox; only their ACL'd secrets)."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "_prompt-helper":
        from key_amnesia.prompt_route import run_prompt_helper

        return run_prompt_helper()

    handlers = {
        "init": cmd_init,
        "passwd": cmd_passwd,
        "change-password": cmd_passwd,
        "set": cmd_set,
        "remove": cmd_remove,
        "import": cmd_import,
        "check": cmd_check,
        "scan": cmd_scan,
        "run": cmd_run,
        "list": cmd_list,
        "unlock": cmd_unlock,
        "lock": cmd_lock,
        "reveal": cmd_reveal,
        "copy": cmd_copy,
        "config": cmd_config,
        "status": cmd_status,
        "connect": cmd_status,  # plain alias — no separate guard verb
        "setup": cmd_setup,
        "docs": cmd_docs,
        "identity": cmd_identity,
        "member": cmd_member,
        "grant": cmd_grant,
        "revoke": cmd_revoke,
        "export": cmd_export,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    # `--name` is a display-only label for the guard's admission prompt —
    # never a credential (see guard.guard_request / default_admit_prompt).
    # Passed via env var so it reaches guard_request() without threading
    # an extra parameter through every command function's call chain.
    name = getattr(args, "name", None)
    if name:
        os.environ["KEY_AMNESIA_CLIENT_NAME"] = name
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
