"""Unit tests for agent/setup_agent.py: manifest construction and upsert logic, no live server."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_module():
    spec = importlib.util.spec_from_file_location("setup_agent", ROOT / "agent" / "setup_agent.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sa = _load_module()

MUTATING = {
    "quarantine_volumes",
    "recycle_snapshots",
    "delete_snapshot_permanently",
    "stop_instances",
    "release_address",
    "quarantine_addresses",
    "restore_volume",
    "restore_snapshot",
    "start_instances",
    "cancel_address_quarantine",
}


def test_warden_manifest_gates_every_mutating_tool():
    m = sa.build_warden_manifest("openai/gpt-x", "be careful")
    assert m["model"] == {"name": "openai/gpt-x", "params": {"temperature": 0.1}}
    assert m["instructions"] == "be careful"
    (server,) = m["mcp_servers"]
    assert server["name"] == "warden"
    assert server["enable_tools"] == ["@all"]
    assert set(server["require_approval_for_tools"]) == MUTATING
    assert len(server["require_approval_for_tools"]) == len(MUTATING)
    assert server["preload"] is True


def test_warden_manifest_config():
    cfg = sa.build_warden_manifest("m", "i")["config"]
    assert cfg == {
        "sandbox": {"enabled": True, "file_downloads": True},
        "generative_ui": {"enabled": True},
        "ask_user_questions": {"enabled": True},
        "dynamic_sub_agents": {"enabled": False},
        "iteration_limit": 60,
    }


def test_reporter_has_only_read_tools():
    m = sa.build_reporter_manifest("m")
    (server,) = m["mcp_servers"]
    assert server["name"] == "warden"
    assert set(server["enable_tools"]) == {
        "warden_status",
        "scan_for_waste",
        "get_plan",
        "list_receipts",
        "get_receipt",
        "list_warden_backups",
        "rollback_window",
        "resource_history",
    }
    assert "watchdog_verify" not in server["enable_tools"]
    assert not (set(server["enable_tools"]) & MUTATING)
    assert "@all" not in server["enable_tools"]
    assert m["config"]["ask_user_questions"]["enabled"] is False
    assert "report" in m["instructions"].lower()


def test_tool_lists_match_the_server_registry():
    import asyncio

    from mcp import Client

    from warden import server

    async def go() -> dict:
        async with Client(server.server) as client:
            return {t.name: t for t in (await client.list_tools()).tools}

    tools = asyncio.run(go())
    assert set(sa.GATED_TOOLS) | set(sa.READ_TOOLS) == set(tools)
    assert not set(sa.GATED_TOOLS) & set(sa.READ_TOOLS)
    for name in sa.READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
    for name in sa.GATED_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
    assert set(sa.REPORTER_TOOLS) <= set(sa.READ_TOOLS)


def test_manifests_validate_against_sdk_models():
    from trueforge_sdk import AgentSpec, RemoteMcpServerManifest

    for m in (sa.build_warden_manifest("m", "i"), sa.build_reporter_manifest("m")):
        spec = AgentSpec.model_validate(m)
        assert spec.mcp_servers[0].name == "warden"
        assert spec.config.iteration_limit in (60, 30)
    server = RemoteMcpServerManifest.model_validate(sa.build_mcp_server_manifest("http://h:8000/mcp"))
    assert server.url == "http://h:8000/mcp"
    assert server.type == "remote"


def test_mcp_server_manifest_has_no_auth():
    m = sa.build_mcp_server_manifest("http://127.0.0.1:8000/mcp")
    assert m["name"] == "warden"
    assert m["type"] == "remote"
    assert "auth" not in m


def test_require_model_missing_is_clear():
    with pytest.raises(sa.SetupError, match="TRUEFORGE_MODEL"):
        sa.require_model({})
    with pytest.raises(sa.SetupError):
        sa.require_model({"TRUEFORGE_MODEL": "  "})
    assert sa.require_model({"TRUEFORGE_MODEL": " a/b "}) == "a/b"


def test_build_payloads_uses_instructions_file_and_default_url():
    p = sa.build_payloads({"TRUEFORGE_MODEL": "a/b"}, reporter=False)
    assert p["mcp_server"]["url"] == sa.DEFAULT_MCP_URL
    assert [a["name"] for a in p["agents"]] == ["warden"]
    agent = p["agents"][0]
    assert agent["description"] == "Approval-gated, reversible AWS cost cleanup"
    expected = (ROOT / "agent" / "instructions.md").read_text(encoding="utf-8").strip()
    assert agent["manifest"]["instructions"] == expected
    json.dumps(p)  # JSON-serialisable


def test_build_payloads_reporter_and_custom_url():
    p = sa.build_payloads({"TRUEFORGE_MODEL": "a/b", "WARDEN_MCP_URL": "http://x:9/mcp"}, reporter=True)
    assert p["mcp_server"]["url"] == "http://x:9/mcp"
    assert [a["name"] for a in p["agents"]] == ["warden", "warden-reporter"]


def test_instructions_file_is_reasonable():
    text = sa.load_instructions()
    assert len(text.split()) <= 1000
    for word in ("warden_status", "scan_for_waste", "IRREVERSIBLE", "CHANGE-RECORD.md", "untrusted"):
        assert word in text
    for word in ("watchdog_verify", "signoff", "rollback_window", "resource_history", "quarantine_addresses"):
        assert word in text
    for tier in ("Safe & reversible", "Needs your review", "Protected"):
        assert tier in text


def test_dry_run_prints_without_calling_server(monkeypatch, capsys):
    monkeypatch.setenv("TRUEFORGE_MODEL", "a/b")
    monkeypatch.setattr(sa, "apply", lambda *a, **k: pytest.fail("dry run must not call TrueForge"))
    assert sa.main(["--dry-run", "--reporter"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["mcp_server"]["name"] == "warden"
    assert len(out["agents"]) == 2


def test_main_missing_model_exits_2(monkeypatch, capsys):
    monkeypatch.setenv("TRUEFORGE_MODEL", "")
    assert sa.main(["--dry-run"]) == 2
    assert "TRUEFORGE_MODEL" in capsys.readouterr().err


class FakeAgents:
    def __init__(self, existing: dict[str, str]):
        self.existing = existing
        self.calls: list[tuple] = []

    def list(self, agent_name=None):
        return [SimpleNamespace(name=n, id=i) for n, i in self.existing.items() if agent_name in n]

    def create(self, name, description, manifest):
        self.calls.append(("create", name))
        return SimpleNamespace(data=SimpleNamespace(id="new-id"))

    def update(self, agent_id, manifest, description):
        self.calls.append(("update", agent_id))
        return SimpleNamespace(data=SimpleNamespace(id=agent_id))


def test_upsert_creates_when_missing():
    # "warden-reporter" exists, but only an exact name match counts.
    agents = FakeAgents({"warden-reporter": "r1"})
    verb, agent_id = sa.upsert_agent(SimpleNamespace(agents=agents), "warden", "d", {})
    assert (verb, agent_id) == ("created", "new-id")
    assert agents.calls == [("create", "warden")]


def test_upsert_updates_when_present():
    agents = FakeAgents({"warden": "w1"})
    verb, agent_id = sa.upsert_agent(SimpleNamespace(agents=agents), "warden", "d", {})
    assert (verb, agent_id) == ("updated", "w1")
    assert agents.calls == [("update", "w1")]


def test_upsert_conflict_falls_back_to_update():
    from trueforge_sdk.errors import ConflictError

    class Racy(FakeAgents):
        def create(self, name, description, manifest):
            self.existing[name] = "late-id"
            raise ConflictError(body={"message": "exists"})

    agents = Racy({})
    verb, agent_id = sa.upsert_agent(SimpleNamespace(agents=agents), "warden", "d", {})
    assert (verb, agent_id) == ("updated", "late-id")


def test_iam_policy_is_valid_and_denies_terminate():
    policy = json.loads((ROOT / "iam" / "warden-policy.json").read_text(encoding="utf-8"))
    assert policy["Version"] == "2012-10-17"
    statements = policy["Statement"]
    assert all({"Sid", "Effect", "Action", "Resource"} <= set(s) for s in statements)
    denies = [s for s in statements if s["Effect"] == "Deny"]
    assert any(s["Action"] == "ec2:TerminateInstances" and s["Resource"] == "*" and "Condition" not in s for s in denies)
    allowed = {a for s in statements if s["Effect"] == "Allow" for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
    assert "ec2:TerminateInstances" not in allowed
    assert not any(a.startswith(("s3:", "iam:")) for a in allowed)
    # KMS keys may only be *used*, and only through EBS (restoring encrypted backups).
    for s in statements:
        acts = [s["Action"]] if isinstance(s["Action"], str) else s["Action"]
        if s["Effect"] == "Allow" and any(a.startswith("kms:") for a in acts):
            assert s["Condition"]["StringLike"]["kms:ViaService"] == "ec2.*.amazonaws.com"
    conditions = json.dumps([s.get("Condition") for s in denies])
    for key in ("aws:ResourceTag/env", "aws:ResourceTag/environment", "aws:ResourceTag/legal-hold"):
        assert key in conditions


def test_outbound_url_guard_rejection_explains_the_fix(monkeypatch, capsys):  # F1
    class Blocked(Exception):
        status_code = 400
        body = {"error": {"message": 'Outbound URL blocked for host "127.0.0.1"'}}

    def apply(*a, **k):
        raise Blocked("400")

    monkeypatch.setenv("TRUEFORGE_MODEL", "a/b")
    monkeypatch.setenv("WARDEN_MCP_URL", "http://127.0.0.1:8000/mcp")
    monkeypatch.setattr(sa, "apply", apply)
    assert sa.main([]) == 1
    err = capsys.readouterr().err
    assert "OUTBOUND_URL_ALLOWED_HOSTS" in err and '"127.0.0.1"' in err
    assert "NETWORK_POLICY_ENABLED=false" in err


def test_env_example_documents_trueforge_network_policy():  # F1 / F2
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "OUTBOUND_URL_ALLOWED_HOSTS" in text and "MCP_REQUEST_TIMEOUT_MS" in text


def test_console_scripts_start_the_server():  # F7
    import tomllib

    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
    assert scripts["warden"] == "warden.server:main"
    assert scripts["warden-server"] == "warden.server:main"


def test_sandbox_fetches_tool_data_itself():  # F5
    for text in (sa.load_instructions(), sa.REPORTER_INSTRUCTIONS):
        assert "from mcp_client import call_tool" in text
        assert "call_tool(\"warden\", \"scan_for_waste\"" in text
        assert "Write the scan JSON" not in text and "write the scan JSON" not in text
    text = sa.load_instructions()
    assert "call_tool(\"warden\", \"get_receipt\"" in text
    assert "write the receipt JSON" not in text


def test_instructions_check_receipts_after_a_tool_timeout():  # F2
    text = sa.load_instructions()
    assert "list_receipts" in text and "time" in text


def test_instructions_explain_review_verdicts_cannot_be_executed():  # demo F4
    text = sa.load_instructions()
    assert "verdict `review`" in text
    assert "rescan" in text.lower() and "env" in text
    assert "quarantine void" in text  # rollback flag wording matches watchdog.rollback_window
