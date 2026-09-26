"""MCP server tests: tool registry, annotations and end-to-end flows under moto."""

from __future__ import annotations

import asyncio
import inspect

import pytest
from mcp import Client

from warden import actions, server
from warden.aws import AwsClients
from warden.config import TAG_QUARANTINED_UNTIL, load_settings

AZ = "us-east-1a"
DEMO = [{"Key": "warden:demo", "Value": "true"}]

READ_TOOLS = {
    "warden_status", "scan_for_waste", "get_plan", "get_receipt", "list_receipts", "list_warden_backups",
    "watchdog_verify", "rollback_window", "resource_history",
}
DESTRUCTIVE_TOOLS = {"quarantine_volumes", "recycle_snapshots", "delete_snapshot_permanently", "release_address"}
REVERSIBLE_TOOLS = {
    "stop_instances", "quarantine_addresses", "restore_volume", "restore_snapshot", "start_instances",
    "cancel_address_quarantine",
}
GATED_EXECUTORS = {
    "quarantine_volumes", "recycle_snapshots", "delete_snapshot_permanently", "stop_instances", "release_address",
    "quarantine_addresses",
}


@pytest.fixture
def wired(aws, tmp_path, monkeypatch):
    """Point the server at moto clients with the demo scope tag; reset afterwards."""
    monkeypatch.setattr(actions, "_sleep", lambda seconds: None)
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


def _address(ec2) -> str:
    return ec2.allocate_address(
        Domain="vpc", TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": DEMO}]
    )["AllocationId"]


def _list_tools() -> list:
    async def go() -> list:
        async with Client(server.server) as client:
            return (await client.list_tools()).tools

    return asyncio.run(go())


def test_registers_exactly_the_19_tools_with_annotations() -> None:
    tools = {t.name: t for t in _list_tools()}
    assert set(tools) == READ_TOOLS | DESTRUCTIVE_TOOLS | REVERSIBLE_TOOLS
    assert len(tools) == 19
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


def test_gated_executors_require_a_signoff_and_say_so() -> None:
    tools = {t.name: t for t in _list_tools()}
    for name in GATED_EXECUTORS:
        schema = tools[name].input_schema
        assert "signoff" in schema["properties"] and "signoff" in schema["required"], name
        assert "watchdog_verify" in tools[name].description and "single use" in tools[name].description
    for name in READ_TOOLS | (REVERSIBLE_TOOLS - GATED_EXECUTORS):
        assert "signoff" not in tools[name].input_schema.get("properties", {}), name
    assert "only records a sign-off" in tools["watchdog_verify"].description
    assert "no AWS" in tools["resource_history"].description


def test_executor_signoff_is_keyword_only_in_actions() -> None:
    for name in GATED_EXECUTORS:
        params = inspect.signature(getattr(actions, name)).parameters
        assert params["signoff"].kind is inspect.Parameter.KEYWORD_ONLY, name


def test_end_to_end_volume_with_watchdog_signoff(wired) -> None:
    ec2 = wired.ec2
    act_vol = _volume(ec2, [{"Key": "Name", "Value": "scratch"}, {"Key": "team", "Value": "data"}])
    keep_vol = _volume(ec2, [{"Key": "env", "Value": "prod"}])

    status = server.warden_status()
    assert status["account_id"] and status["scope"] == "warden:demo=true" and status["max_batch"] == 5
    assert status["quarantine_minutes"] == 10080 and status["ledger"]["ok"] is True
    assert "watchdog_verify" in status["approval_rule"]

    report = server.scan_for_waste()
    assert "error" not in report, report
    by_id = {f["resource_id"]: f for f in report["findings"]}
    assert by_id[act_vol]["verdict"] == "act" and by_id[act_vol]["action"] == "quarantine_volume"
    assert by_id[act_vol]["tier"] == "safe_reversible" and by_id[act_vol]["why"]
    assert by_id[keep_vol]["verdict"] == "keep" and by_id[keep_vol]["tier"] == "protected"
    assert act_vol in report["summary"]["decision_list"]
    plan_id = report["plan_id"]
    assert server.get_plan(plan_id)["items"][act_vol]["verdict"] == "act"

    # Without a genuine Watchdog sign-off the executor refuses everything.
    forged = server.quarantine_volumes(plan_id, [act_vol], "wd-20260101T000000-abcdef." + "0" * 64)
    assert forged["counts"]["done"] == 0
    assert "Watchdog sign-off rejected" in forged["results"][0]["detail"]
    assert ec2.describe_volumes(VolumeIds=[act_vol])["Volumes"]

    # The Watchdog blocks the keep id, wildcards and unknown plans; it approves only the act id.
    blocked = server.watchdog_verify(plan_id, "quarantine_volume", [keep_vol])
    assert blocked["signoff"] is None and keep_vol in blocked["blocked"]
    assert server.watchdog_verify(plan_id, "quarantine_volume", ["*"])["signoff"] is None
    assert server.watchdog_verify("plan-nope", "quarantine_volume", [act_vol])["signoff"] is None

    signed = server.watchdog_verify(plan_id, "quarantine_volume", [act_vol])
    assert signed["approved_ids"] == [act_vol] and signed["signoff"], signed
    assert any("fingerprint" in line for line in signed["checks"])

    # A token signed for one id cannot carry another (and a rejection does not consume it).
    smuggle = server.quarantine_volumes(plan_id, [act_vol, keep_vol], signed["signoff"])
    assert smuggle["counts"]["done"] == 0

    receipt = server.quarantine_volumes(plan_id, [act_vol], signed["signoff"])
    assert receipt["counts"] == {"done": 1, "skipped": 0, "failed": 0}, receipt
    result = receipt["results"][0]
    backup = result["backup_snapshot_id"]
    assert result["undo"] == {"tool": "restore_volume", "args": {"backup_snapshot_id": backup}}

    # Single use: replaying the same sign-off is rejected.
    replay = server.quarantine_volumes(plan_id, [act_vol], signed["signoff"])
    assert replay["counts"]["done"] == 0
    assert "already used" in replay["results"][0]["detail"]

    assert server.get_receipt(receipt["receipt_id"])["receipt_id"] == receipt["receipt_id"]
    listed = server.list_receipts()["receipts"]
    assert receipt["receipt_id"] in {r["receipt_id"] for r in listed}
    backups = server.list_warden_backups()["backups"]
    assert [b["backup_of"] for b in backups if b["snapshot_id"] == backup] == [act_vol]

    window = server.rollback_window()
    assert "error" not in window, window
    (item,) = [i for i in window["items"] if i.get("backup_snapshot_id") == backup]
    assert item["resource_id"] == act_vol and item["state"] == "backup"
    assert item["seconds_remaining"] > 0 and item["countdown"] not in ("expired", "no deadline")
    assert item["undo"] == {"tool": "restore_volume", "args": {"backup_snapshot_id": backup}}
    assert window["ledger"]["ok"] is True

    history = server.resource_history(act_vol)
    events = [e["event"] for e in history["entries"]]
    assert history["count"] == len(events) and history["ledger"]["ok"] is True
    for event in ("watchdog_signoff", "watchdog_signoff_consumed", "action_item", "watchdog_signoff_rejected"):
        assert event in events, events
    # Newest first: the replay rejection comes before the successful consumption.
    assert events.index("watchdog_signoff_rejected") < events.index("watchdog_signoff_consumed")
    seqs = [e["seq"] for e in history["entries"]]
    assert seqs == sorted(seqs, reverse=True)

    restored = server.restore_volume(backup)
    assert restored["counts"]["done"] == 1, restored
    new_vols = ec2.describe_volumes(Filters=[{"Name": "tag:warden:restored-from", "Values": [backup]}])["Volumes"]
    assert len(new_vols) == 1
    tags = {t["Key"]: t["Value"] for t in new_vols[0]["Tags"]}
    assert tags["Name"] == "scratch" and tags["team"] == "data"


def test_end_to_end_elastic_ip_quarantine_then_release(wired, clock) -> None:
    ec2 = wired.ec2
    alloc = _address(ec2)

    report = server.scan_for_waste()
    finding = {f["resource_id"]: f for f in report["findings"]}[alloc]
    assert finding["verdict"] == "act" and finding["action"] == "quarantine_address" and finding["reversible"]
    plan_id = report["plan_id"]

    signed = server.watchdog_verify(plan_id, "quarantine_address", [alloc])
    assert signed["approved_ids"] == [alloc], signed
    receipt = server.quarantine_addresses(plan_id, [alloc], signed["signoff"])
    assert receipt["counts"]["done"] == 1, receipt
    assert receipt["results"][0]["undo"] == {"tool": "cancel_address_quarantine", "args": {"allocation_id": alloc}}
    assert receipt["est_monthly_savings_usd"] == 0

    # An immediate release is refused: by the plan, the scan, the Watchdog and the executor.
    assert server.watchdog_verify(plan_id, "release_address", [alloc])["signoff"] is None
    rescan = server.scan_for_waste()
    early = {f["resource_id"]: f for f in rescan["findings"]}[alloc]
    assert early["verdict"] == "keep" and "releasable in" in early["reasons"][0]
    assert server.watchdog_verify(rescan["plan_id"], "release_address", [alloc])["signoff"] is None
    refused = server.release_address(rescan["plan_id"], alloc, "wd-20260101T000000-abcdef." + "0" * 64)
    assert refused["counts"]["done"] == 0
    assert ec2.describe_addresses(AllocationIds=[alloc])["Addresses"]

    window = server.rollback_window()
    (item,) = [i for i in window["items"] if i["resource_id"] == alloc]
    assert item["state"] == "quarantined" and item["seconds_remaining"] > 0
    assert item["undo"] == {"tool": "cancel_address_quarantine", "args": {"allocation_id": alloc}}
    assert "irreversible" in item["finalize"]

    # Time passes: the whole quarantine window (quarantine_minutes) elapses; tags and receipt are untouched.
    assert TAG_QUARANTINED_UNTIL in {t["Key"] for t in ec2.describe_addresses(AllocationIds=[alloc])["Addresses"][0]["Tags"]}
    clock.advance(server.warden_status()["quarantine_minutes"] * 60 + 60)
    later = server.scan_for_waste()
    ready = {f["resource_id"]: f for f in later["findings"]}[alloc]
    assert ready["verdict"] == "act" and ready["action"] == "release_address" and not ready["reversible"]
    assert ready["tier"] == "needs_review"

    sig = server.watchdog_verify(later["plan_id"], "release_address", [alloc])
    assert sig["approved_ids"] == [alloc], sig
    released = server.release_address(later["plan_id"], alloc, sig["signoff"])
    assert released["counts"]["done"] == 1, released
    assert not ec2.describe_addresses()["Addresses"]

    events = [e["event"] for e in server.resource_history(alloc)["entries"]]
    assert events.count("watchdog_signoff_consumed") == 2 and "watchdog_block" in events


def test_cancel_address_quarantine_undoes_the_tags(wired) -> None:
    ec2 = wired.ec2
    alloc = _address(ec2)
    assert server.cancel_address_quarantine(alloc)["counts"]["done"] == 0  # not quarantined: refused
    report = server.scan_for_waste()
    sig = server.watchdog_verify(report["plan_id"], "quarantine_address", [alloc])
    assert server.quarantine_addresses(report["plan_id"], [alloc], sig["signoff"])["counts"]["done"] == 1
    undone = server.cancel_address_quarantine(alloc)
    assert undone["counts"]["done"] == 1, undone
    tags = {t["Key"] for t in ec2.describe_addresses(AllocationIds=[alloc])["Addresses"][0].get("Tags", [])}
    assert TAG_QUARANTINED_UNTIL not in tags


def test_tool_errors_are_json_not_tracebacks(wired) -> None:
    assert "error" in server.get_plan("../../etc/passwd")
    assert "error" in server.get_receipt("rcpt-missing")
    assert server.resource_history("vol-never-seen")["count"] == 0


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
    report = server.scan_for_waste()
    frozen = server.watchdog_verify(report["plan_id"], "quarantine_volume", ["vol-1"])
    assert frozen["signoff"] is None and "frozen" in frozen["blocked"]["vol-1"]


def test_scan_description_says_review_needs_a_tag_and_rescan() -> None:  # demo F4
    desc = {t.name: t for t in _list_tools()}["scan_for_waste"].description
    assert "'review'" in desc and "rescan" in desc and "env" in desc
