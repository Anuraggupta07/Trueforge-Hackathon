"""Tests for warden.watchdog: independent verification, HMAC single-use sign-offs, rollback window."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from warden import audit, scanner, watchdog
from warden import plan as plan_mod
from warden.config import (
    TAG_BACKUP_OF,
    TAG_EXPIRES_AT,
    TAG_QUARANTINED_AT,
    TAG_QUARANTINED_UNTIL,
    TAG_STOPPED_AT,
)

AZ = "us-east-1b"
AMI = "ami-12c6146b"
_ID_KEY = {"volume": "VolumeId", "snapshot": "SnapshotId", "instance": "InstanceId", "address": "AllocationId"}


# ---------------------------------------------------------------- helpers


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tagspec(rtype: str, tags: dict[str, str]) -> list[dict]:
    return [{"ResourceType": rtype, "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}] if tags else []


def make_volume(aws, tags=None) -> dict:
    vol = aws.ec2.create_volume(AvailabilityZone=AZ, Size=10, VolumeType="gp3",
                                TagSpecifications=_tagspec("volume", tags or {}))
    return aws.ec2.describe_volumes(VolumeIds=[vol["VolumeId"]])["Volumes"][0]


def make_snapshot(aws, tags=None) -> dict:
    vol = make_volume(aws)
    snap = aws.ec2.create_snapshot(VolumeId=vol["VolumeId"], TagSpecifications=_tagspec("snapshot", tags or {}))
    return aws.ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"][0]


def make_instance(aws, tags=None) -> dict:
    res = aws.ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                                TagSpecifications=_tagspec("instance", tags or {}))
    iid = res["Instances"][0]["InstanceId"]
    return aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]


def make_address(aws, tags=None) -> dict:
    alloc = aws.ec2.allocate_address(Domain="vpc", TagSpecifications=_tagspec("elastic-ip", tags or {}))
    return aws.ec2.describe_addresses(AllocationIds=[alloc["AllocationId"]])["Addresses"][0]


def make_plan(aws, settings, entries) -> str:
    """entries = [(resource_type, action, described_resource)]."""
    items = [
        plan_mod.PlanItem(res[_ID_KEY[rtype]], rtype, "act", action, plan_mod.fingerprint(rtype, res))
        for rtype, action, res in entries
    ]
    plan = plan_mod.new_plan(aws.account_id(), settings.region, items, settings)
    plan_mod.save_plan(plan, settings)
    return plan.plan_id


def ledger_events(settings) -> list[str]:
    path = settings.state_dir / "audit.jsonl"
    return [json.loads(line)["event"] for line in path.read_text(encoding="utf-8").splitlines()]


REAL_DNS_INDEX = scanner.dns_index


@pytest.fixture(autouse=True)
def quiet_neighbours(monkeypatch):
    """Scanner helpers default to 'nothing references it' (individual tests override)."""
    monkeypatch.setattr(scanner, "dns_index", lambda clients, **kw: {}, raising=False)
    monkeypatch.setattr(scanner, "lb_target_instances", lambda clients, **kw: {}, raising=False)


def _approved_volume(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    result = watchdog.verify(aws, settings, pid, "quarantine_volume", [vol["VolumeId"]])
    assert result["approved_ids"] == [vol["VolumeId"]] and result["token"]
    return vol, pid, result


# ---------------------------------------------------------------- verify


def test_verify_approves_unchanged_item_and_persists_signoff(aws, settings):
    vol, pid, result = _approved_volume(aws, settings)
    vid = vol["VolumeId"]
    assert result["blocked"] == {}
    assert result["signoff_id"].startswith("wd-") and result["token"].startswith(result["signoff_id"] + ".")
    assert any("fingerprint" in c for c in result["checks"])
    record = json.loads((settings.state_dir / "signoffs" / f"{result['signoff_id']}.json").read_text())
    assert record["approved_ids"] == [vid] and record["plan_id"] == pid and record["action"] == "quarantine_volume"
    assert record["fingerprints"] == {vid: plan_mod.fingerprint("volume", vol)}
    assert len((settings.state_dir / "watchdog.key").read_bytes()) == 32
    assert "watchdog_signoff" in ledger_events(settings)

    ok, reason, fps = watchdog.check_signoff(settings, result["token"], pid, "quarantine_volume", [vid])
    assert (ok, reason) == (True, "ok") and fps == {vid: record["fingerprints"][vid]}
    assert ledger_events(settings)[-1] == "watchdog_signoff_consumed"
    assert audit.verify_ledger(settings)["ok"]


def test_verify_frozen_blocks_everything(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    (settings.state_dir / "FREEZE").write_text("")
    result = watchdog.verify(aws, settings, pid, "quarantine_volume", [vol["VolumeId"]])
    assert result["token"] is None and result["approved_ids"] == []
    assert "frozen" in result["blocked"][vol["VolumeId"]]
    assert ledger_events(settings)[-1] == "watchdog_block"
    assert not (settings.state_dir / "signoffs").exists()


def test_verify_blocks_invalid_plan_request(aws, settings):
    result = watchdog.verify(aws, settings, "plan-nope", "quarantine_volume", ["vol-1"])
    assert result["token"] is None and "not found" in result["blocked"]["vol-1"]


def test_verify_blocks_fingerprint_drift(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    aws.ec2.create_tags(Resources=[vol["VolumeId"]], Tags=[{"Key": "note", "Value": "hi"}])
    result = watchdog.verify(aws, settings, pid, "quarantine_volume", [vol["VolumeId"]])
    assert result["token"] is None and "changed since the scan" in result["blocked"][vol["VolumeId"]]


def test_verify_blocks_retagged_production(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    aws.ec2.create_tags(Resources=[vol["VolumeId"]], Tags=[{"Key": "env", "Value": "production"}])
    result = watchdog.verify(aws, settings, pid, "quarantine_volume", [vol["VolumeId"]])
    assert "production" in result["blocked"][vol["VolumeId"]]


def test_verify_blocks_attached_volume(aws, settings, monkeypatch):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    real = aws.ec2.describe_volumes

    def attached(**kw):
        out = real(**kw)
        for v in out["Volumes"]:
            v["State"] = "in-use"
        return out

    monkeypatch.setattr(aws.ec2, "describe_volumes", attached)
    result = watchdog.verify(aws, settings, pid, "quarantine_volume", [vol["VolumeId"]])
    assert result["token"] is None and vol["VolumeId"] in result["blocked"]


def test_verify_blocks_ami_referenced_snapshot(aws, settings):
    inst = make_instance(aws)
    image_id = aws.ec2.create_image(InstanceId=inst["InstanceId"], Name="golden-image")["ImageId"]
    image = aws.ec2.describe_images(ImageIds=[image_id])["Images"][0]
    snap_id = image["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"]
    snap = aws.ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]
    free = make_snapshot(aws)
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap), ("snapshot", "recycle_snapshot", free)])
    result = watchdog.verify(aws, settings, pid, "recycle_snapshot", [snap_id, free["SnapshotId"]])
    assert image_id in result["blocked"][snap_id] and "AMI" in result["blocked"][snap_id]
    assert result["approved_ids"] == [free["SnapshotId"]] and result["token"]


def test_verify_blocks_instance_in_target_group(aws, settings, monkeypatch):
    inst = make_instance(aws)
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])
    monkeypatch.setattr(scanner, "lb_target_instances", lambda clients, **kw: {iid: ["web-tg"]}, raising=False)
    result = watchdog.verify(aws, settings, pid, "stop_instance", [iid])
    assert result["token"] is None and "target group web-tg" in result["blocked"][iid]


def test_verify_fails_closed_when_lb_check_errors(aws, settings, monkeypatch):
    inst = make_instance(aws)
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])

    def boom(clients, **kw):
        raise RuntimeError("elbv2 down")

    monkeypatch.setattr(scanner, "lb_target_instances", boom, raising=False)
    result = watchdog.verify(aws, settings, pid, "stop_instance", [inst["InstanceId"]])
    assert result["token"] is None and "could not check" in result["blocked"][inst["InstanceId"]]


def test_verify_approves_idle_instance(aws, settings):
    inst = make_instance(aws)
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])
    result = watchdog.verify(aws, settings, pid, "stop_instance", [inst["InstanceId"]])
    assert result["approved_ids"] == [inst["InstanceId"]]


def test_verify_blocks_dns_referenced_address(aws, settings, monkeypatch):
    addr = make_address(aws)
    alloc, ip = addr["AllocationId"], addr["PublicIp"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    monkeypatch.setattr(
        scanner, "dns_index", lambda clients, **kw: {ip: ["app.example.com. (A) in zone example.com."]}, raising=False,
    )
    result = watchdog.verify(aws, settings, pid, "quarantine_address", [alloc])
    assert result["token"] is None
    assert "app.example.com." in result["blocked"][alloc] and "subdomain takeover" in result["blocked"][alloc]


def test_verify_quarantine_address_approved_when_unreferenced(aws, settings):
    addr = make_address(aws)
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    result = watchdog.verify(aws, settings, pid, "quarantine_address", [addr["AllocationId"]])
    assert result["approved_ids"] == [addr["AllocationId"]]


@pytest.mark.parametrize(
    "tags, expect",
    [
        ({}, "must be quarantined first"),
        ({TAG_QUARANTINED_UNTIL: _iso(datetime.now(timezone.utc) + timedelta(hours=2))}, "still in quarantine"),
        ({TAG_QUARANTINED_UNTIL: "garbage"}, "not a valid time"),
        ({TAG_QUARANTINED_UNTIL: _iso(datetime.now(timezone.utc) - timedelta(minutes=1))}, None),
    ],
)
def test_verify_release_only_after_quarantine_window(aws, settings, tags, expect):
    addr = make_address(aws, tags)
    alloc = addr["AllocationId"]
    if tags:
        addr = warden_quarantine_receipt(aws, settings, alloc)
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    result = watchdog.verify(aws, settings, pid, "release_address", [alloc])
    if expect is None:
        assert result["approved_ids"] == [alloc] and result["token"]
        assert any("quarantine window ended" in c for c in result["checks"])
    else:
        assert result["token"] is None and expect in result["blocked"][alloc]


# ---------------------------------------------------------------- check_signoff


def test_check_signoff_is_single_use(aws, settings):
    vol, pid, result = _approved_volume(aws, settings)
    args = (settings, result["token"], pid, "quarantine_volume", [vol["VolumeId"]])
    assert watchdog.check_signoff(*args)[0] is True
    ok, reason, fps = watchdog.check_signoff(*args)
    assert ok is False and "already used" in reason and fps == {}
    assert ledger_events(settings)[-1] == "watchdog_signoff_rejected"


def test_check_signoff_rejects_forged_hmac(aws, settings):
    vol, pid, result = _approved_volume(aws, settings)
    sid, mac = result["token"].split(".")
    forged = f"{sid}.{('0' if mac[0] != '0' else '1') + mac[1:]}"
    ok, reason, _ = watchdog.check_signoff(settings, forged, pid, "quarantine_volume", [vol["VolumeId"]])
    assert ok is False and "signature mismatch" in reason


def test_check_signoff_rejects_altered_record(aws, settings):
    vol, pid, result = _approved_volume(aws, settings)
    path = settings.state_dir / "signoffs" / f"{result['signoff_id']}.json"
    record = json.loads(path.read_text())
    record["approved_ids"].append("vol-extra")
    path.write_text(json.dumps(record))
    ok, reason, _ = watchdog.check_signoff(settings, result["token"], pid, "quarantine_volume", ["vol-extra"])
    assert ok is False and "signature mismatch" in reason


def test_check_signoff_rejects_expired(aws, settings):
    vol, pid, result = _approved_volume(aws, settings)
    later = time.time() + settings.signoff_ttl_minutes * 60 + 5
    ok, reason, _ = watchdog.check_signoff(
        settings, result["token"], pid, "quarantine_volume", [vol["VolumeId"]], now=later
    )
    assert ok is False and "expired" in reason


def test_check_signoff_rejects_wrong_action_and_plan(aws, settings):
    vol, pid, result = _approved_volume(aws, settings)
    ok, reason, _ = watchdog.check_signoff(settings, result["token"], pid, "stop_instance", [vol["VolumeId"]])
    assert ok is False and "not stop_instance" in reason
    ok, reason, _ = watchdog.check_signoff(settings, result["token"], "plan-other", "quarantine_volume",
                                           [vol["VolumeId"]])
    assert ok is False and "not plan-other" in reason
    # Rejections do not consume the sign-off.
    assert watchdog.check_signoff(settings, result["token"], pid, "quarantine_volume", [vol["VolumeId"]])[0]


def test_check_signoff_rejects_id_not_approved(aws, settings):
    vol, pid, result = _approved_volume(aws, settings)
    ok, reason, _ = watchdog.check_signoff(
        settings, result["token"], pid, "quarantine_volume", [vol["VolumeId"], "vol-sneaky"]
    )
    assert ok is False and "vol-sneaky not approved" in reason


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "no-dot-here",
        "wd-abc." + "g" * 64,
        "wd-abc.ab",
        "../plans/plan-x." + "a" * 64,
        "wd-..\\..\\x." + "a" * 64,
        "wd-a/b." + "a" * 64,
        "wd-abc.def." + "a" * 64,
    ],
)
def test_check_signoff_rejects_malformed_and_path_traversal(settings, token):
    ok, reason, _ = watchdog.check_signoff(settings, token, "plan-x", "quarantine_volume", ["vol-1"])
    assert ok is False and reason == "malformed sign-off token"


def test_check_signoff_rejects_unknown_id(settings):
    ok, reason, _ = watchdog.check_signoff(settings, "wd-20260101T000000-abcdef." + "a" * 64, "plan-x",
                                           "quarantine_volume", ["vol-1"])
    assert ok is False and reason == "unknown sign-off id"


# ---------------------------------------------------------------- rollback window


def test_countdown_format():
    assert watchdog.countdown(6 * 86400 + 23 * 3600 + 10 * 60 + 5) == "6d 23h 10m"
    assert watchdog.countdown(2 * 3600 + 5 * 60) == "2h 5m"
    assert watchdog.countdown(252) == "4m 12s"
    assert watchdog.countdown(0) == "expired" and watchdog.countdown(-5) == "expired"


def test_rollback_window_lists_every_source(aws, settings):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    # Backup of a deleted volume.
    backup = make_snapshot(aws, {TAG_BACKUP_OF: "vol-gone", TAG_EXPIRES_AT: _iso(now + timedelta(days=7))})
    # Stopped by Warden, still stopped.
    stopped = make_instance(aws, {TAG_STOPPED_AT: _iso(now)})
    aws.ec2.stop_instances(InstanceIds=[stopped["InstanceId"]])
    # Stopped by Warden but restarted by someone else.
    restarted = make_instance(aws, {TAG_STOPPED_AT: _iso(now)})
    # Quarantined EIP, and one that got associated again.
    quarantined = make_address(aws, {TAG_QUARANTINED_AT: _iso(now),
                                     TAG_QUARANTINED_UNTIL: _iso(now + timedelta(minutes=5))})
    reused = make_address(aws, {TAG_QUARANTINED_AT: _iso(now),
                                TAG_QUARANTINED_UNTIL: _iso(now + timedelta(minutes=5))})
    aws.ec2.associate_address(AllocationId=reused["AllocationId"], InstanceId=restarted["InstanceId"])
    make_address(aws)  # untouched: not listed
    # Recycled by Warden (receipt); moto has no Recycle Bin API -> estimated end time + flag.
    audit.save_receipt(settings, {
        "receipt_id": audit.new_id("rcpt"), "action": "recycle_snapshot", "plan_id": "plan-x",
        "finished_at": _iso(now),
        "results": [{"resource_id": "snap-recycled", "status": "done",
                     "undo": {"tool": "restore_snapshot", "args": {"snapshot_id": "snap-recycled"}}},
                    {"resource_id": "snap-skipped", "status": "skipped"}],
    })
    audit.audit(settings, "scan", plan_id="plan-x")

    report = watchdog.rollback_window(aws, settings, now=now.timestamp())
    by_id = {i["resource_id"]: i for i in report["items"]}
    assert report["ledger"]["ok"] is True and report["generated_at"] == _iso(now)
    assert set(by_id) == {"vol-gone", stopped["InstanceId"], restarted["InstanceId"],
                          quarantined["AllocationId"], reused["AllocationId"], "snap-recycled"}

    b = by_id["vol-gone"]
    assert b["state"] == "backup" and b["countdown"] == "7d 0h 0m"
    assert b["undo"] == {"tool": "restore_volume", "args": {"backup_snapshot_id": backup["SnapshotId"]}}

    s = by_id[stopped["InstanceId"]]
    assert s["state"] == "stopped" and s["undo"]["tool"] == "start_instances" and s["flags"] == []
    r = by_id[restarted["InstanceId"]]
    assert r["undo"] is None and any("restarted outside Warden" in f for f in r["flags"])

    q = by_id[quarantined["AllocationId"]]
    assert q["state"] == "quarantined" and q["countdown"] == "5m 0s" and q["seconds_remaining"] == 300
    assert q["undo"] == {"tool": "cancel_address_quarantine", "args": {"allocation_id": quarantined["AllocationId"]}}
    assert "release_address" in q["finalize"] and q["flags"] == []
    assert any("in use again - quarantine void" in f for f in by_id[reused["AllocationId"]]["flags"])

    rc = by_id["snap-recycled"]
    assert rc["state"] == "recycled" and rc["countdown"] == "7d 0h 0m"
    assert rc["undo"] == {"tool": "restore_snapshot", "args": {"snapshot_id": "snap-recycled"}}
    assert any("Recycle Bin API unavailable" in f for f in rc["flags"])
    # Soonest deadline first; no-deadline items last.
    assert report["items"][0]["seconds_remaining"] == 300
    assert report["items"][-1]["until"] is None


def test_rollback_window_uses_recycle_bin_exit_time(aws, settings, monkeypatch):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    audit.save_receipt(settings, {
        "receipt_id": audit.new_id("rcpt"), "action": "recycle_snapshot", "plan_id": "plan-x",
        "finished_at": _iso(now), "results": [{"resource_id": "snap-a", "status": "done"},
                                              {"resource_id": "snap-b", "status": "done"}],
    })

    def list_bin(SnapshotIds=None, **_):
        return {"Snapshots": [{"SnapshotId": "snap-a", "RecycleBinExitTime": now + timedelta(hours=3)}]}

    monkeypatch.setattr(aws.ec2, "list_snapshots_in_recycle_bin", list_bin, raising=False)
    report = watchdog.rollback_window(aws, settings, now=now.timestamp())
    by_id = {i["resource_id"]: i for i in report["items"]}
    assert by_id["snap-a"]["countdown"] == "3h 0m" and by_id["snap-a"]["flags"] == []
    gone = by_id["snap-b"]  # not in the bin and not a live snapshot: retention ended
    assert gone["countdown"] == "expired" and gone["undo"] is None and "not recoverable" in gone["flags"][0]


def test_rollback_window_degrades_when_an_api_fails(aws, settings, monkeypatch):
    def boom(**_):
        raise RuntimeError("no ec2 for you")

    monkeypatch.setattr(aws.ec2, "describe_addresses", boom)
    report = watchdog.rollback_window(aws, settings)
    assert report["items"] == [] and any("quarantined Elastic IPs unavailable" in n for n in report["notes"])
    assert report["ledger"]["ok"] is True


def test_watchdog_does_not_import_actions():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(watchdog))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(a.name for a in node.names)
            names.add(node.module or "")
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
    assert "actions" not in names and "warden.actions" not in names


def test_verify_fails_closed_when_dns_check_errors(aws, settings, monkeypatch):
    addr = make_address(aws)
    alloc = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    monkeypatch.setattr(scanner, "dns_index", REAL_DNS_INDEX)  # real helper, Route 53 broken

    def denied(*a, **k):
        raise RuntimeError("route53 down")

    monkeypatch.setattr(aws.route53, "list_hosted_zones", denied)
    monkeypatch.setattr(aws.route53, "can_paginate", lambda name: False)
    result = watchdog.verify(aws, settings, pid, "quarantine_address", [alloc])
    assert result["token"] is None and "could not check DNS" in result["blocked"][alloc]


# ---------------------------------------------------------------- review fixes


def warden_quarantine_receipt(aws, settings, alloc, at="2020-01-01T00:00:00Z") -> dict:
    """Tag warden:quarantined-at as Warden does, write the matching receipt, return the fresh address."""
    aws.ec2.create_tags(Resources=[alloc], Tags=[{"Key": TAG_QUARANTINED_AT, "Value": at}])
    audit.save_receipt(settings, {
        "receipt_id": audit.new_id("rcpt"), "action": "quarantine_address", "plan_id": "plan-x", "finished_at": at,
        "results": [{"resource_id": alloc, "status": "done", "quarantined_at": at}],
    })
    return aws.ec2.describe_addresses(AllocationIds=[alloc])["Addresses"][0]


def _expired_quarantine(aws, settings, receipt=True) -> dict:
    past = _iso(datetime.now(timezone.utc) - timedelta(minutes=1))
    addr = make_address(aws, {TAG_QUARANTINED_AT: "2020-01-01T00:00:00Z", TAG_QUARANTINED_UNTIL: past})
    return warden_quarantine_receipt(aws, settings, addr["AllocationId"]) if receipt else addr


def test_verify_release_refused_without_warden_quarantine_receipt(aws, settings):  # bypass F1
    addr = _expired_quarantine(aws, settings, receipt=False)
    alloc = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    result = watchdog.verify(aws, settings, pid, "release_address", [alloc])
    assert result["token"] is None and "not set by Warden" in result["blocked"][alloc]


def test_verify_release_refused_after_use_during_quarantine(aws, settings):  # bypass F1 / demo F2
    addr = _expired_quarantine(aws, settings)
    alloc = addr["AllocationId"]
    inst = make_instance(aws)
    assoc = aws.ec2.associate_address(AllocationId=alloc, InstanceId=inst["InstanceId"])["AssociationId"]
    window = watchdog.rollback_window(aws, settings)
    (item,) = [i for i in window["items"] if i["resource_id"] == alloc]
    assert any("quarantine void" in f for f in item["flags"])
    aws.ec2.disassociate_address(AssociationId=assoc)
    addr = aws.ec2.describe_addresses(AllocationIds=[alloc])["Addresses"][0]
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    result = watchdog.verify(aws, settings, pid, "release_address", [alloc])
    assert result["token"] is None and "void" in result["blocked"][alloc]


def test_verify_builds_the_dns_index_once_per_call(aws, settings, monkeypatch):  # demo F6
    a, b = make_address(aws), make_address(aws)
    pid = make_plan(aws, settings, [("address", "quarantine_address", a), ("address", "quarantine_address", b)])
    calls = []
    monkeypatch.setattr(scanner, "dns_index", lambda clients, **kw: calls.append(kw) or {}, raising=False)
    result = watchdog.verify(aws, settings, pid, "quarantine_address", [a["AllocationId"], b["AllocationId"]])
    assert len(result["approved_ids"]) == 2 and calls == [{"strict": True}]


def test_rollback_window_marks_restored_backup(aws, settings):  # demo F3
    backup = make_snapshot(aws, {TAG_BACKUP_OF: "vol-orig", TAG_EXPIRES_AT: "2999-01-01T00:00:00Z"})
    sid = backup["SnapshotId"]
    audit.save_receipt(settings, {
        "receipt_id": audit.new_id("rcpt"), "action": "restore_volume", "plan_id": None,
        "finished_at": "2026-01-01T00:00:00Z",
        "results": [{"resource_id": sid, "status": "done", "restored_volume_id": "vol-new"}],
    })
    (item,) = [i for i in watchdog.rollback_window(aws, settings)["items"] if i["resource_id"] == "vol-orig"]
    assert item["undo"] is None and any("already restored as vol-new" in f for f in item["flags"])
