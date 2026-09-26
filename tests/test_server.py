"""MCP server tests: tool registry, annotations and an end-to-end flow under moto."""

from __future__ import annotations

import asyncio

import pytest
from mcp import Client

from warden import server
from warden.aws import AwsClients
from warden.config import load_settings

AZ = "us-east-1a"
DEMO = [{"Key": "warden:demo", "Value": "true"}]

READ_TOOLS = {"warden_status", "scan_for_waste", "get_plan", "get_receipt", "list_receipts", "list_warden_backups"}
DESTRUCTIVE_TOOLS = {"quarantine_volumes", "recycle_snapshots", "delete_snapshot_permanently", "release_address"}
REVERSIBLE_TOOLS = {"stop_instances", "restore_volume", "restore_snapshot", "start_instances"}


@pytest.fixture
def wired(aws, tmp_path):
    """Point the server at moto clients with the demo scope tag; reset afterwards."""
    settings = load_settings(
        env={"AWS_REGION": "us-east-1", "WARDEN_STATE_DIR": str(tmp_path / "srv"), "WARDEN_SCOPE_TAG": "warden:demo=true"}
    )
    clients = AwsClients(settings)
    server.configure(settings, clients)
    yield clients
    server.configure()


def _volume(ec2, extra: list[dict]) -> str:
    return ec2.create_volume(
        AvailabilityZone=AZ, Size=10, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": DEMO + extra}],
    )["VolumeId"]


def _list_tools() -> list:
    async def go() -> list:
        async with Client(server.server) as client:
            return (await client.list_tools()).tools

    return asyncio.run(go())


def test_registers_exactly_the_14_tools_with_annotations() -> None:
    tools = {t.name: t for t in _list_tools()}
    assert set(tools) == READ_TOOLS | DESTRUCTIVE_TOOLS | REVERSIBLE_TOOLS
    assert len(tools) == 14
    for name, tool in tools.items():
        ann = tool.annotations
        assert tool.title and tool.description
        if name in READ_TOOLS:
            assert ann.read_only_hint is True
        elif name in DESTRUCTIVE_TOOLS:
            assert ann.read_only_hint is False and ann.destructive_hint is True
            assert "IRREVERSIBLE" in tool.description or "REVERSIBLE" in tool.description
        else:
            assert ann.read_only_hint is False and ann.destructive_hint is False
    for name in ("delete_snapshot_permanently", "release_address"):
        assert "IRREVERSIBLE" in tools[name].description


def test_end_to_end_quarantine_receipt_restore(wired) -> None:
    ec2 = wired.ec2
    act_vol = _volume(ec2, [{"Key": "Name", "Value": "scratch"}, {"Key": "team", "Value": "data"}])
    keep_vol = _volume(ec2, [{"Key": "env", "Value": "prod"}])

    status = server.warden_status()
    assert status["account_id"] and status["scope"] == "warden:demo=true" and status["max_batch"] == 5

    report = server.scan_for_waste()
    assert "error" not in report, report
    by_id = {f["resource_id"]: f for f in report["findings"]}
    assert by_id[act_vol]["verdict"] == "act" and by_id[act_vol]["action"] == "quarantine_volume"
    assert by_id[keep_vol]["verdict"] == "keep"
    plan_id = report["plan_id"]
    assert server.get_plan(plan_id)["items"][act_vol]["verdict"] == "act"

    # Plan lock: a keep id is rejected even inside a valid plan.
    rejected = server.quarantine_volumes(plan_id, [keep_vol])
    assert rejected["counts"]["done"] == 0 and rejected["results"][0]["status"] == "skipped"
    assert ec2.describe_volumes(VolumeIds=[keep_vol])["Volumes"]

    # Wildcards and unknown plans never act.
    assert server.quarantine_volumes(plan_id, ["*"])["counts"]["done"] == 0
    assert server.quarantine_volumes("plan-nope", [act_vol])["counts"]["done"] == 0

    receipt = server.quarantine_volumes(plan_id, [act_vol])
    assert receipt["counts"] == {"done": 1, "skipped": 0, "failed": 0}, receipt
    result = receipt["results"][0]
    backup = result["backup_snapshot_id"]
    assert result["undo"] == {"tool": "restore_volume", "args": {"backup_snapshot_id": backup}}

    assert server.get_receipt(receipt["receipt_id"])["receipt_id"] == receipt["receipt_id"]
    listed = server.list_receipts()["receipts"]
    assert receipt["receipt_id"] in {r["receipt_id"] for r in listed}
    backups = server.list_warden_backups()["backups"]
    assert [b["backup_of"] for b in backups if b["snapshot_id"] == backup] == [act_vol]

    restored = server.restore_volume(backup)
    assert restored["counts"]["done"] == 1, restored
    new_vols = ec2.describe_volumes(Filters=[{"Name": "tag:warden:restored-from", "Values": [backup]}])["Volumes"]
    assert len(new_vols) == 1
    tags = {t["Key"]: t["Value"] for t in new_vols[0]["Tags"]}
    assert tags["Name"] == "scratch" and tags["team"] == "data"


def test_tool_errors_are_json_not_tracebacks(wired) -> None:
    assert "error" in server.get_plan("../../etc/passwd")
    assert "error" in server.get_receipt("rcpt-missing")


def test_via_in_memory_client(wired) -> None:
    async def go() -> dict:
        async with Client(server.server) as client:
            result = await client.call_tool("warden_status", {})
            return result.structured_content

    status = asyncio.run(go())
    assert status["region"] == "us-east-1" and "approval_rule" in status


def test_status_reports_runtime_freeze_file(wired, tmp_path) -> None:  # S14
    assert server.warden_status()["freeze"] is False
    state = tmp_path / "srv"
    state.mkdir(parents=True, exist_ok=True)
    (state / "FREEZE").write_text("", encoding="utf-8")
    assert server.warden_status()["freeze"] is True
