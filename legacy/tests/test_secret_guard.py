"""PreToolUse/preToolUse secret-guard hook: detection + host deny contracts."""

from __future__ import annotations

import io
import json

import pytest

from key_amnesia.hooks import secret_guard as sg


# --- true positives: known prefixes -----------------------------------------

KNOWN_PREFIX_SAMPLES = [
    ("sk-" + "a" * 25, "OpenAI-style key"),
    ("sk-ant-" + "a" * 25, "Anthropic-style key"),
    ("AKIA" + "0" * 16, "AWS access key id"),
    ("ghp_" + "a" * 25, "GitHub PAT"),
    ("github_pat_" + "a" * 25, "GitHub fine-grained PAT"),
    ("glpat-" + "a" * 25, "GitLab PAT"),
    ("xoxb-" + "a" * 25, "Slack token"),
    ("AIza" + "a" * 25, "Google API key"),
    ("sk_live_" + "a" * 25, "Stripe secret key"),
    ("rk_live_" + "a" * 25, "Stripe restricted key"),
    ("npm_" + "a" * 25, "npm token"),
]


@pytest.mark.parametrize("token,expected_kind", KNOWN_PREFIX_SAMPLES)
def test_known_prefixes_block(token: str, expected_kind: str) -> None:
    text = f"curl -H 'Authorization: {token}' https://example.com"
    assert sg.find_finding(text) == expected_kind


def test_bearer_token_blocks() -> None:
    text = "curl -H 'Authorization: Bearer abcdEFGH12345678ijkl' https://example.com"
    assert sg.find_finding(text) == "Bearer token"


def test_high_entropy_assignment_blocks() -> None:
    text = "export API_KEY=aB3xQ9mK2pL7vN4wZ8"
    finding = sg.find_finding(text)
    assert finding is not None
    assert "assignment" in finding


def test_high_entropy_assignment_blocks_quoted() -> None:
    text = 'TOKEN="Zk9pL2xQ7mN4vB8w"'
    assert sg.find_finding(text) is not None


# --- false positives (advisory-safe / must not block) -----------------------


def test_password_placeholder_allowed() -> None:
    assert sg.find_finding("PASSWORD=test123") is None


def test_bare_api_key_mention_allowed() -> None:
    assert sg.find_finding("echo API_KEY is required") is None


def test_comment_mentioning_secret_allowed() -> None:
    assert sg.find_finding("# this function handles the secret rotation") is None


def test_changeme_placeholder_allowed() -> None:
    assert sg.find_finding("TOKEN=changeme") is None


def test_ka_run_command_allowed_even_with_secret_name() -> None:
    text = "ka run --secret API_KEY --as API_KEY=API_KEY -- python app.py"
    assert sg.find_finding(text) is None


def test_ka_set_command_allowed() -> None:
    assert sg.find_finding("ka set OPENAI_API_KEY") is None


def test_empty_text_allowed() -> None:
    assert sg.find_finding("") is None


# --- host detection + deny shapes -------------------------------------------


def test_detect_host_claude_default() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}
    assert sg.detect_host(payload) == "claude"


def test_detect_host_cursor_by_event_name() -> None:
    payload = {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {}}
    assert sg.detect_host(payload) == "cursor"


def test_detect_host_cursor_by_unique_fields() -> None:
    payload = {
        "conversation_id": "abc",
        "cursor_version": "1.7.2",
        "tool_name": "Shell",
        "tool_input": {},
    }
    assert sg.detect_host(payload) == "cursor"


def test_deny_claude_shape() -> None:
    reply = sg.deny_claude("OpenAI-style key")
    hso = reply["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "ka set" in hso["permissionDecisionReason"]
    assert "ka run" in hso["permissionDecisionReason"]


def test_deny_cursor_shape() -> None:
    reply = sg.deny_cursor("OpenAI-style key")
    assert reply["permission"] == "deny"
    assert "agent_message" in reply
    assert "user_message" in reply
    assert "ka set" in reply["agent_message"] or "ka run" in reply["agent_message"]


# --- main() end-to-end (stdin JSON -> stdout JSON) --------------------------


def _run_main(payload: dict, monkeypatch: pytest.MonkeyPatch, capsys) -> tuple[int, dict | None]:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    rc = sg.main()
    out = capsys.readouterr().out.strip()
    return rc, (json.loads(out) if out else None)


def test_main_claude_bash_blocks(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "export TOKEN=" + "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_main_cursor_shell_blocks(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "preToolUse",
        "cursor_version": "1.7.2",
        "conversation_id": "abc",
        "tool_name": "Shell",
        "tool_input": {"command": "export TOKEN=" + "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["permission"] == "deny"


def test_main_write_tool_scans_contents(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "x.env", "contents": "AKIA" + "0" * 16},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None


def test_main_codex_apply_patch_blocks_claude_shape(monkeypatch, capsys) -> None:
    """Codex apply_patch uses Claude-shaped PreToolUse deny."""
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": {"command": "*** Update File: .env\n+" + "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_main_clean_command_allows(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello world"},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_main_ignores_unmatched_tool(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"command": "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_main_disable_env_skips_everything(monkeypatch, capsys) -> None:
    monkeypatch.setenv(sg.DISABLE_ENV, "1")
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "export TOKEN=" + "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_main_fails_open_on_malformed_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not json{{{"))
    rc = sg.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert out == ""


def test_main_fails_open_on_empty_stdin(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    rc = sg.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert out == ""


def test_main_fails_open_on_non_dict_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(["not", "a", "dict"])))
    rc = sg.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert out == ""


# --- verb deny (load-bearing) ------------------------------------------------


DENY_SHELL_SAMPLES = [
    "ka set FOO bar",
    "ka remove FOO",
    "ka import .env",
    "ka passwd",
    "ka init",
    "ka unlock",
    "ka grant FOO --to bob",
    "ka revoke FOO --to bob",
    "ka member add bob --pubkey x --role runner",
    "ka member remove bob",
    "ka config set session-mode cached",
    "ka reveal FOO",
    "ka export FOO",
    "ka copy FOO",
    "ka setup",
    "ka identity create",
    "ka scan --yes",
]


def _claude_payload(command: str, tool_name: str = "Bash") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {"command": command},
    }


def _codex_payload(command: str, tool_name: str = "Bash") -> dict:
    # Codex-like: Claude PreToolUse shape, no Cursor markers.
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {"command": command},
    }


def _cursor_payload(command: str) -> dict:
    return {
        "hook_event_name": "preToolUse",
        "cursor_version": "1.7.2",
        "conversation_id": "abc",
        "tool_name": "Shell",
        "tool_input": {"command": command},
    }


@pytest.mark.parametrize("command", DENY_SHELL_SAMPLES)
def test_verb_deny_claude_shape(command: str, monkeypatch, capsys) -> None:
    rc, reply = _run_main(_claude_payload(command), monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "own terminal" in reply["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("command", DENY_SHELL_SAMPLES)
def test_verb_deny_codex_like_shape(command: str, monkeypatch, capsys) -> None:
    rc, reply = _run_main(_codex_payload(command), monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert "permission" not in reply
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("command", DENY_SHELL_SAMPLES)
def test_verb_deny_cursor_shape(command: str, monkeypatch, capsys) -> None:
    rc, reply = _run_main(_cursor_payload(command), monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["permission"] == "deny"
    assert "hookSpecificOutput" not in reply
    assert "own terminal" in reply["agent_message"]


def test_write_tool_does_not_verb_deny_ka_set(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "README.md",
            "contents": "Store secrets with `ka set NAME` in your own terminal.",
        },
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_ka_safe_does_not_suppress_verb_deny(monkeypatch, capsys) -> None:
    """_KA_SAFE matches `ka set` but verb deny still fires."""
    rc, reply = _run_main(_claude_payload("ka set API_KEY sk-ant-" + "a" * 25), monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = reply["hookSpecificOutput"]["permissionDecisionReason"]
    assert "ka set" in reason
    assert "own terminal" in reason


def test_nested_run_set_denied(monkeypatch, capsys) -> None:
    rc, reply = _run_main(
        _claude_payload("ka run --secret N --as N=E -- ka set FOO bar"),
        monkeypatch,
        capsys,
    )
    assert reply is not None
    reason = reply["hookSpecificOutput"]["permissionDecisionReason"]
    assert "wrapping" in reason
    assert "ka set" in reason


def test_chained_secret_after_ka_run_denied(monkeypatch, capsys) -> None:
    token = "sk-ant-" + "a" * 25
    cmd = (
        "ka run --secret X --as X=V -- python a.py && "
        f'curl -H "Authorization: Bearer {token}"'
    )
    rc, reply = _run_main(_claude_payload(cmd), monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = reply["hookSpecificOutput"]["permissionDecisionReason"]
    assert "Anthropic" in reason or "Bearer" in reason


def test_pipe_tail_after_ka_run_no_finding(monkeypatch, capsys) -> None:
    cmd = "ka run --secret X --as X=V -- python a.py | tail -30"
    rc, reply = _run_main(_claude_payload(cmd), monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_nested_run_python_allowed(monkeypatch, capsys) -> None:
    rc, reply = _run_main(
        _claude_payload("ka run --secret N --as N=E -- python script.py"),
        monkeypatch,
        capsys,
    )
    assert rc == 0
    assert reply is None


def test_trailing_secret_after_run_denied(monkeypatch, capsys) -> None:
    cmd = "ka run --secret N --as N=E -- python deploy.py --api-key " + "sk-ant-" + "a" * 25
    rc, reply = _run_main(_claude_payload(cmd), monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "Anthropic" in reply["hookSpecificOutput"]["permissionDecisionReason"]


def test_ordinary_ka_run_no_trailing_finding(monkeypatch, capsys) -> None:
    cmd = "ka run --secret NAME --as NAME=VAR -- python script.py"
    rc, reply = _run_main(_claude_payload(cmd), monkeypatch, capsys)
    assert rc == 0
    assert reply is None


@pytest.mark.parametrize("tool_name", ["bash", "shell"])
def test_opencode_bridge_contract_verb_deny(tool_name: str, monkeypatch, capsys) -> None:
    """Pin the deny JSON the OpenCode JS plugin parses. Always exit 0."""
    payload = {"tool_name": tool_name, "tool_input": {"command": "ka reveal FOO"}}
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    hso = reply["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert hso["permissionDecisionReason"]
    assert "reveal" in hso["permissionDecisionReason"]


@pytest.mark.parametrize("tool_name", ["bash", "shell"])
def test_opencode_bridge_contract_clean_allow(tool_name: str, monkeypatch, capsys) -> None:
    payload = {"tool_name": tool_name, "tool_input": {"command": "echo hi"}}
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_opencode_write_content_key_denied(monkeypatch, capsys) -> None:
    payload = {
        "tool_name": "write",
        "tool_input": {"filePath": "/tmp/x.env", "content": "AKIA" + "0" * 16},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_opencode_edit_newString_denied_via_collect_strings(monkeypatch, capsys) -> None:
    """OpenCode edit args use camelCase newString, which matches no key in
    `_command_text`. Coverage is the collect_strings fallback — this test is
    what fails if that fallback is ever removed.
    """
    payload = {
        "tool_name": "edit",
        "tool_input": {
            "filePath": "/tmp/x.env",
            "oldString": "placeholder",
            "newString": "AKIA" + "0" * 16,
        },
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_opencode_cd_led_export_denied(monkeypatch, capsys) -> None:
    """permission.bash globs cannot see this chain; the plugin must."""
    payload = {
        "tool_name": "bash",
        "tool_input": {"command": "cd /tmp && ka export"},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "export" in reply["hookSpecificOutput"]["permissionDecisionReason"]


def test_opencode_js_skips_nothing_the_python_guard_allows() -> None:
    """The JS bridge guards everything but SKIP, so SKIP must stay disjoint.

    Until 0.4.16 the plugin held a GUARDED allow-list and this test asserted it
    was a superset of ``_ALLOWED_TOOL_NAMES``. That premise died when the filter
    was inverted to cover MCP tools, whose OpenCode tool ids we cannot name. The
    invariant survives in its complementary form: no tool the Python guard
    inspects may appear in the JS skip set.
    """
    import re
    from importlib import resources

    js = (
        resources.files("key_amnesia") / "plugins" / "opencode" / "secret-guard.js"
    ).read_text(encoding="utf-8")
    assert "const GUARDED" not in js, "filter is inverted; GUARDED must be gone"
    match = re.search(r"const SKIP = new Set\(\[([\s\S]*?)\]\)", js)
    assert match is not None, "SKIP set not found in secret-guard.js"
    skipped = set(re.findall(r'"([^"]+)"', match.group(1)))
    assert sg._ALLOWED_TOOL_NAMES.isdisjoint(skipped)
    # `webfetch` carries a URL, and a URL can carry a token in a query param.
    assert "webfetch" not in skipped

    # Anything forwarded under its own spelling must be a name this module
    # actually inspects; otherwise the bridge would forward it to a guard that
    # early-returns, which is the no-op 0.4.16 exists to remove.
    native = re.search(r"const NATIVE = new Set\(\[([\s\S]*?)\]\)", js)
    assert native is not None, "NATIVE set not found in secret-guard.js"
    assert set(re.findall(r'"([^"]+)"', native.group(1))) <= sg._ALLOWED_TOOL_NAMES


# --- MCP tool calls (same PreToolUse event, `mcp__<server>__<tool>`) --------


MCP_NAME_SAMPLES = [
    "mcp__github__create_issue",
    "mcp__slack__post_message",
    "mcp__claude_ai_Gmail__send_message",
    "MCP__Github__Create_Issue",
    "mcp__some-server__do__it",
]


@pytest.mark.parametrize("name", MCP_NAME_SAMPLES)
def test_is_mcp_tool_name_accepts(name: str) -> None:
    assert sg.is_mcp_tool_name(name)


@pytest.mark.parametrize(
    "name",
    ["Bash", "Write", "apply_patch", "mcp", "mcp__", "mcpfoo__bar", "", "Read"],
)
def test_is_mcp_tool_name_rejects(name: str) -> None:
    assert not sg.is_mcp_tool_name(name)


def _mcp_payload(tool_input: object, tool: str = "mcp__github__create_issue") -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}


def test_mcp_inline_credential_denied(monkeypatch, capsys) -> None:
    """The gap this closes: today such a call passes the guard entirely."""
    payload = _mcp_payload(
        {"title": "deploy notes", "body": "run with --api-key " + "sk-ant-" + "a" * 25}
    )
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    hso = reply["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "Anthropic" in hso["permissionDecisionReason"]


def test_mcp_credential_nested_in_arguments_denied(monkeypatch, capsys) -> None:
    """MCP argument shapes are server-defined; collect_strings must reach them."""
    payload = _mcp_payload(
        {
            "channel": "#ops",
            "blocks": [{"text": {"type": "mrkdwn", "value": "AKIA" + "0" * 16}}],
        },
        tool="mcp__slack__post_message",
    )
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_mcp_known_key_does_not_shadow_sibling_argument(monkeypatch, capsys) -> None:
    """A server arg literally named `command` must not hide a sibling secret."""
    payload = _mcp_payload(
        {"command": "echo hi", "env_note": "ghp_" + "a" * 25},
        tool="mcp__docker__exec",
    )
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert "GitHub" in reply["hookSpecificOutput"]["permissionDecisionReason"]


def test_mcp_clean_arguments_allowed(monkeypatch, capsys) -> None:
    payload = _mcp_payload({"title": "docs", "body": "describe the setup flow"})
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_mcp_verb_deny_stays_shell_only(monkeypatch, capsys) -> None:
    """An MCP call is not a shell command: `ka reveal` in its args is not denied."""
    payload = _mcp_payload(
        {"path": "notes.md", "contents": "run `ka reveal FOO` yourself"},
        tool="mcp__filesystem__write_file",
    )
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_mcp_non_dict_arguments_fail_open(monkeypatch, capsys) -> None:
    for tool_input in (12345, None, ["a", "b"]):
        rc, reply = _run_main(_mcp_payload(tool_input), monkeypatch, capsys)
        assert rc == 0
        assert reply is None


def test_mcp_cursor_shaped_payload_uses_cursor_deny(monkeypatch, capsys) -> None:
    """Cursor routes MCP to beforeMCPExecution today; if one ever arrives on
    preToolUse the deny shape must still be Cursor's flat one.
    """
    payload = {
        "hook_event_name": "preToolUse",
        "cursor_version": "1.7.2",
        "tool_name": "mcp__stripe__create_charge",
        "tool_input": {"note": "key " + "sk_live_" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["permission"] == "deny"
    assert "hookSpecificOutput" not in reply


def test_mcp_not_added_to_allowed_tool_names() -> None:
    """MCP is matched by shape, not by an entry in the fixed allow set."""
    assert not any(n.startswith("mcp") for n in sg._ALLOWED_TOOL_NAMES)


def test_ka_scan_without_yes_allowed(monkeypatch, capsys) -> None:
    rc, reply = _run_main(_claude_payload("ka scan --deep --no-import"), monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_find_finding_ka_safe_skips_prefix_but_trailing_scan_does_not() -> None:
    prefix = "ka run --secret NAME --as NAME=VAR -- python script.py"
    assert sg.find_finding(prefix) is None
    trailing = "python deploy.py --api-key " + "sk-ant-" + "a" * 25
    assert sg.find_finding(prefix + " " + trailing) is None  # _KA_SAFE on full text
    assert sg.find_finding(trailing, ignore_ka_safe=True) is not None


def test_function_call_assignment_allowed() -> None:
    assert sg.find_finding("token = secrets.token_hex(8)") is None
    assert sg.find_finding("new_token = secrets_mod.token_urlsafe(32)") is None
    assert sg.find_finding("Token = GetTokenFromCache()") is None


def test_type_annotation_allowed() -> None:
    assert sg.find_finding("token: Optional[str]") is None


def test_json_quoted_key_likely_denied() -> None:
    text = '{"api_key": "aB3xQ9mK2pL7vN4wZ8"}'
    finding = sg.find_finding(text)
    assert finding is not None
    assert "assignment" in finding


def test_passphrase_still_hook_denied() -> None:
    assert sg.find_finding("export PASSWORD=CorrectHorseBattery") is not None
    assert sg.find_finding("secret = CorrectHorseBattery") is not None



# --- union: flag-form credential (branch A) inside MCP arguments (branch B) --
#
# Neither half covers this. Before 0.4.16 the space-separated flag form was
# detected nowhere, and MCP calls never reached the detector at all. The value
# below is an authored fake with no vendor prefix, so no known-prefix rule can
# rescue the case: the deny depends on the flag anchor *and* on MCP arguments
# being scanned.

UNION_FAKE_VALUE = "Xq4vP9mL2kR7nB3wZ6tY"


def test_union_fake_value_has_no_vendor_prefix() -> None:
    """Guards the premise: the fixture must not be catchable by prefix alone."""
    assert sg.find_finding(UNION_FAKE_VALUE) is None
    assert sg.find_finding(f"note: {UNION_FAKE_VALUE}") is None


def test_union_mcp_flag_form_non_vendor_value_denied(monkeypatch, capsys) -> None:
    payload = _mcp_payload(
        {
            "title": "deploy runbook",
            "body": f"deploy with --api-key {UNION_FAKE_VALUE}",
        },
        tool="mcp__github__create_issue",
    )
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    hso = reply["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "--api-key flag value" in hso["permissionDecisionReason"]
    assert UNION_FAKE_VALUE not in hso["permissionDecisionReason"]


def test_union_mcp_flag_form_in_sibling_argument_denied(monkeypatch, capsys) -> None:
    """A server arg named `command` must not shadow a flag-form sibling."""
    payload = _mcp_payload(
        {
            "command": "echo hi",
            "notes": f"then run --password {UNION_FAKE_VALUE}",
        },
        tool="mcp__docker__exec",
    )
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert "--password flag value" in reply["hookSpecificOutput"]["permissionDecisionReason"]


def test_union_cursor_shaped_mcp_flag_form_keeps_flat_deny(monkeypatch, capsys) -> None:
    """Same union payload on Cursor's contract: flat shape, no hookSpecificOutput."""
    payload = _mcp_payload(
        {"body": f"deploy with --api-key {UNION_FAKE_VALUE}"},
        tool="mcp__github__create_issue",
    )
    payload["hook_event_name"] = "preToolUse"
    payload["cursor_version"] = "1.7.2"
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert "hookSpecificOutput" not in reply
    assert reply["permission"] == "deny"
    assert "--api-key flag value" in reply["agent_message"]
    assert "--api-key flag value" in reply["user_message"]
    assert UNION_FAKE_VALUE not in json.dumps(reply)


def test_union_clean_mcp_payload_stays_silent(monkeypatch, capsys) -> None:
    """Flag-shaped but non-qualifying args: end-anchored vocabulary + indirection."""
    payload = _mcp_payload(
        {
            "title": "ci notes",
            "body": (
                "use --token-file ./t.txt, --password-stdin, "
                '--secret-name prod/db/password and --token "$GITHUB_TOKEN"'
            ),
        },
        tool="mcp__github__create_issue",
    )
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_union_ka_run_recommended_path_not_denied(monkeypatch, capsys) -> None:
    """The path key-amnesia tells agents to use must stay usable."""
    rc, reply = _run_main(
        _claude_payload("ka run --secret SOME_NAME -- cmd"), monkeypatch, capsys
    )
    assert rc == 0
    assert reply is None
    rc, reply = _run_main(
        _claude_payload("ka run --secret SOME_NAME --as SOME_NAME=API_KEY -- ./deploy.sh"),
        monkeypatch,
        capsys,
    )
    assert rc == 0
    assert reply is None
