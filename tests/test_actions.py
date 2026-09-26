"""Tests for warden.actions (moto-backed; plans are built directly, not via the scanner)."""

from __future__ import annotations

import dataclasses
import json
import time

import pytest
from botocore.exceptions import WaiterError

from warden import actions, audit
from warden import plan as plan_mod
from warden.config import (
    TAG_BACKUP_OF,
    TAG_EXPIRES_AT,
    TAG_RECYCLE,
    TAG_RESTORE_AZ,
    TAG_RESTORED_FROM,
    TAG_STOPPED_AT,
)
from warden.policy import tags_to_dict

AZ = "us-east-1b"
AMI = "ami-12c6146b"


# ---------------------------------------------------------------- helpers


def _tagspec(rtype: str, tags: dict[str, str]) -> list[dict]:
    return [{"ResourceType": rtype, "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}] if tags else []


def make_volume(aws, tags: dict[str, str] | None = None, vtype: str = "gp3", size: int = 10) -> dict:
    vol = aws.ec2.create_volume(
        AvailabilityZone=AZ, Size=size, VolumeType=vtype, TagSpecifications=_tagspec("volume", tags or {})
    )
    return aws.ec2.describe_volumes(VolumeIds=[vol["VolumeId"]])["Volumes"][0]


def make_snapshot(aws, tags: dict[str, str] | None = None) -> dict:
    vol = make_volume(aws)
    snap = aws.ec2.create_snapshot(VolumeId=vol["VolumeId"], TagSpecifications=_tagspec("snapshot", tags or {}))
    return aws.ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"][0]


def make_instance(aws, tags: dict[str, str] | None = None) -> dict:
    res = aws.ec2.run_instances(
        ImageId=AMI, MinCount=1, MaxCount=1, InstanceType="t3.micro",
        TagSpecifications=_tagspec("instance", tags or {}),
    )
    iid = res["Instances"][0]["InstanceId"]
    return aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]


def make_address(aws, tags: dict[str, str] | None = None) -> dict:
    alloc = aws.ec2.allocate_address(Domain="vpc", TagSpecifications=_tagspec("elastic-ip", tags or {}))
    return aws.ec2.describe_addresses(AllocationIds=[alloc["AllocationId"]])["Addresses"][0]


WARDEN_RULE = {
    "Status": "available",
    "RetentionPeriod": {"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
    "ResourceTags": [{"ResourceTagKey": "warden:recycle", "ResourceTagValue": "true"}],
}

_ID_KEY = {"volume": "VolumeId", "snapshot": "SnapshotId", "instance": "InstanceId", "address": "AllocationId"}


def make_plan(aws, settings, entries: list[tuple[str, str, dict]], verdict: str = "act", now: float | None = None) -> str:
    """entries = [(resource_type, action, described_resource)]."""
    items = [
        plan_mod.PlanItem(
            resource_id=res[_ID_KEY[rtype]],
            resource_type=rtype,
            verdict=verdict,
            action=action if verdict == "act" else None,
            fingerprint=plan_mod.fingerprint(rtype, res),
        )
        for rtype, action, res in entries
    ]
    plan = plan_mod.new_plan(aws.account_id(), settings.region, items, settings, now=now)
    plan_mod.save_plan(plan, settings)
    return plan.plan_id


def statuses(receipt: dict) -> list[str]:
    return [r["status"] for r in receipt["results"]]


def audit_lines(settings) -> list[dict]:
    path = settings.state_dir / "audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def recycle_bin(aws, monkeypatch):
    """Pretend a Recycle Bin rule exists and emulate the rbin EC2 APIs moto lacks."""
    binned: set[str] = set()
    real_delete = aws.ec2.delete_snapshot

    def delete_snapshot(**kw):
        out = real_delete(**kw)
        binned.add(kw["SnapshotId"])
        return out

    def list_in_bin(SnapshotIds=None, **_):
        return {"Snapshots": [{"SnapshotId": s} for s in (SnapshotIds or binned) if s in binned]}

    def restore_from_bin(SnapshotId, **_):
        binned.discard(SnapshotId)
        return {"SnapshotId": SnapshotId}

    monkeypatch.setattr(actions, "_recycle_rules", lambda clients: [WARDEN_RULE])
    monkeypatch.setattr(aws.ec2, "delete_snapshot", delete_snapshot)
    monkeypatch.setattr(aws.ec2, "list_snapshots_in_recycle_bin", list_in_bin)
    monkeypatch.setattr(aws.ec2, "restore_snapshot_from_recycle_bin", restore_from_bin)
    monkeypatch.setattr(aws.ec2, "delete_tags", lambda **kw: {})  # snapshot is gone in moto
    return binned


# ---------------------------------------------------------------- quarantine_volume


def test_quarantine_happy_path_backup_then_delete(aws, settings):
    vol = make_volume(aws, {"Name": "old-data", "team": "web", "warden:demo": "true"})
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid])

    assert statuses(receipt) == ["done"], receipt
    res = receipt["results"][0]
    snap_id = res["backup_snapshot_id"]
    assert res["undo"] == {"tool": "restore_volume", "args": {"backup_snapshot_id": snap_id}}
    assert receipt["counts"] == {"done": 1, "skipped": 0, "failed": 0}
    assert receipt["est_monthly_savings_usd"] == pytest.approx(0.8)
    assert receipt["plan_id"] == pid and receipt["action"] == "quarantine_volume"
    assert receipt["account_id"] == "123456789012" and receipt["freeze"] is False
    assert aws.ec2.describe_volumes(Filters=[{"Name": "volume-id", "Values": [vid]}])["Volumes"] == []

    snap = aws.ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]
    tags = tags_to_dict(snap["Tags"])
    assert tags[TAG_BACKUP_OF] == vid
    assert tags[TAG_RESTORE_AZ] == AZ
    assert tags["warden:restore-type"] == "gp3" and tags["warden:restore-size"] == "10"
    assert tags["warden:plan-id"] == pid and TAG_EXPIRES_AT in tags
    assert tags["team"] == "web" and tags["Name"] == "old-data"
    assert "Warden backup of" in snap["Description"]


def test_receipt_persisted_and_audit_written(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]])

    assert audit.load_receipt(settings, receipt["receipt_id"]) == receipt
    assert audit.list_receipts(settings)[0]["receipt_id"] == receipt["receipt_id"]
    events = [(e["event"], e.get("receipt_id")) for e in audit_lines(settings)]
    assert ("action_item", receipt["receipt_id"]) in events
    assert ("action", receipt["receipt_id"]) in events


def test_backup_not_completed_keeps_volume(aws, settings, monkeypatch):
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])

    class SlowWaiter:
        def wait(self, **_):
            raise WaiterError(name="SnapshotCompleted", reason="Max attempts exceeded", last_response={})

    monkeypatch.setattr(aws.ec2, "get_waiter", lambda name: SlowWaiter())
    receipt = actions.quarantine_volumes(aws, settings, pid, [vid])

    res = receipt["results"][0]
    assert res["status"] == "skipped"
    assert "backup not complete; volume kept" in res["detail"]
    assert res["backup_snapshot_id"]
    assert aws.ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["State"] == "available"


def test_volume_reattached_after_plan_is_skipped(aws, settings):
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    inst = make_instance(aws)
    aws.ec2.attach_volume(VolumeId=vid, InstanceId=inst["InstanceId"], Device="/dev/sdf")

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid])

    assert statuses(receipt) == ["skipped"]
    assert "changed since approval" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_volumes(VolumeIds=[vid])["Volumes"]
    backups = aws.ec2.describe_snapshots(Filters=[{"Name": f"tag:{TAG_BACKUP_OF}", "Values": [vid]}])
    assert backups["Snapshots"] == []


def test_retagged_production_after_plan_is_skipped(aws, settings):
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    aws.ec2.create_tags(Resources=[vid], Tags=[{"Key": "Env", "Value": "Production"}])

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid])

    res = receipt["results"][0]
    assert res["status"] == "skipped"
    assert "changed since approval" in res["detail"] and "production" in res["detail"]
    assert aws.ec2.describe_volumes(VolumeIds=[vid])["Volumes"]


def test_innocent_tag_change_is_fingerprint_drift(aws, settings):
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    aws.ec2.create_tags(Resources=[vid], Tags=[{"Key": "owner", "Value": "alice"}])

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid])
    assert statuses(receipt) == ["skipped"]
    assert "changed since approval" in receipt["results"][0]["detail"]


def test_volume_gone_is_skipped(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    aws.ec2.delete_volume(VolumeId=vol["VolumeId"])

    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]])
    assert receipt["results"][0]["detail"] == "no longer exists"


def test_scope_tag_removed_after_plan_is_skipped(aws, settings):
    scoped = dataclasses.replace(settings, scope_tag_key="warden:demo", scope_tag_value="true")
    vol = make_volume(aws, {"warden:demo": "true"})
    vid = vol["VolumeId"]
    pid = make_plan(aws, scoped, [("volume", "quarantine_volume", vol)])
    aws.ec2.delete_tags(Resources=[vid], Tags=[{"Key": "warden:demo"}])

    receipt = actions.quarantine_volumes(aws, scoped, pid, [vid])
    assert statuses(receipt) == ["skipped"]
    assert "no longer in scope" in receipt["results"][0]["detail"]


# ---------------------------------------------------------------- request-level guards


def test_freeze_refuses_everything(aws, settings):
    frozen = dataclasses.replace(settings, freeze=True)
    vol = make_volume(aws)
    pid = make_plan(aws, frozen, [("volume", "quarantine_volume", vol)])

    receipt = actions.quarantine_volumes(aws, frozen, pid, [vol["VolumeId"]])

    assert receipt["freeze"] is True
    assert statuses(receipt) == ["skipped"]
    assert receipt["results"][0]["detail"] == actions.FROZEN_DETAIL
    assert aws.ec2.describe_volumes(VolumeIds=[vol["VolumeId"]])["Volumes"]


def test_freeze_blocks_undo_tools_too(aws, settings):
    frozen = dataclasses.replace(settings, freeze=True)
    assert statuses(actions.restore_volume(aws, frozen, "snap-12345678")) == ["skipped"]
    assert statuses(actions.start_instances(aws, frozen, ["i-12345678"])) == ["skipped"]
    assert statuses(actions.restore_snapshot(aws, frozen, "snap-12345678")) == ["skipped"]


def test_wrong_plan_id(aws, settings):
    vol = make_volume(aws)
    receipt = actions.quarantine_volumes(aws, settings, "plan-does-not-exist", [vol["VolumeId"]])
    assert statuses(receipt) == ["skipped"]
    assert "not found" in receipt["results"][0]["detail"]


def test_id_not_in_plan_rejected(aws, settings):
    planned, other = make_volume(aws), make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", planned)])

    receipt = actions.quarantine_volumes(aws, settings, pid, [other["VolumeId"]])
    assert statuses(receipt) == ["skipped"]
    assert "not in plan" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_volumes(VolumeIds=[other["VolumeId"]])["Volumes"]


def test_keep_verdict_rejected(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)], verdict="keep")
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]])
    assert "not 'act'" in receipt["results"][0]["detail"]


def test_expired_plan(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)], now=time.time() - 2 * 3600)
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]])
    assert statuses(receipt) == ["skipped"]
    assert "expired" in receipt["results"][0]["detail"]


def test_batch_over_cap(aws, settings):
    vols = [make_volume(aws) for _ in range(settings.max_batch + 1)]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", v) for v in vols])
    receipt = actions.quarantine_volumes(aws, settings, pid, [v["VolumeId"] for v in vols])
    assert statuses(receipt) == ["skipped"] * len(vols)
    assert "exceeds the limit" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_volumes()["Volumes"]) == len(vols)


@pytest.mark.parametrize("ids", [[], ["*"], ["all"], ["vol-*"]])
def test_empty_and_wildcard_rejected(aws, settings, ids):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    receipt = actions.quarantine_volumes(aws, settings, pid, ids)
    assert receipt["counts"]["done"] == 0
    assert set(statuses(receipt)) == {"skipped"}


def test_irreversible_with_two_ids_rejected(aws, settings):
    a, b = make_address(aws), make_address(aws)
    pid = make_plan(aws, settings, [("address", "release_address", a), ("address", "release_address", b)])
    ids = [a["AllocationId"], b["AllocationId"]]
    # Bypass the single-id signature to prove the gate itself enforces it.
    receipt = actions._run_gated(aws, settings, "release_address", pid, ids, actions._release_one)
    assert statuses(receipt) == ["skipped", "skipped"]
    assert "exactly one id" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 2


def test_wrong_action_for_plan_item(aws, settings):
    snap = make_snapshot(aws)
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.delete_snapshot_permanently(aws, settings, pid, snap["SnapshotId"])
    assert statuses(receipt) == ["skipped"]
    assert "not 'delete_snapshot'" in receipt["results"][0]["detail"]


# ---------------------------------------------------------------- snapshots


def test_recycle_snapshot_happy_path(aws, settings, recycle_bin, monkeypatch):
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    tagged: list[dict] = []
    real_create_tags = aws.ec2.create_tags

    def spy(**kw):
        tagged.append(kw)
        return real_create_tags(**kw)

    monkeypatch.setattr(aws.ec2, "create_tags", spy)
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid])

    assert statuses(receipt) == ["done"], receipt
    assert "verified" in receipt["results"][0]["detail"]
    assert receipt["results"][0]["undo"] == {"tool": "restore_snapshot", "args": {"snapshot_id": sid}}
    assert {"Key": TAG_RECYCLE, "Value": "true"} in tagged[0]["Tags"]
    assert sid in recycle_bin


def test_recycle_refused_without_recycle_bin_rule(aws, settings, monkeypatch):
    snap = make_snapshot(aws)
    monkeypatch.setattr(actions, "_recycle_rules", lambda clients: [])
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.recycle_snapshots(aws, settings, pid, [snap["SnapshotId"]])
    assert statuses(receipt) == ["skipped"]
    assert "Recycle Bin rule missing" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"]


def test_recycle_verification_unavailable_degrades(aws, settings, monkeypatch):
    snap = make_snapshot(aws)
    monkeypatch.setattr(actions, "_recycle_rules", lambda clients: [WARDEN_RULE])
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.recycle_snapshots(aws, settings, pid, [snap["SnapshotId"]])
    assert statuses(receipt) == ["done"]
    assert "verification unavailable" in receipt["results"][0]["detail"]


def test_restore_snapshot_only_if_warden_recycled(aws, settings, recycle_bin):
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    assert "not recycled by Warden" in actions.restore_snapshot(aws, settings, sid)["results"][0]["detail"]

    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    assert statuses(actions.recycle_snapshots(aws, settings, pid, [sid])) == ["done"]
    receipt = actions.restore_snapshot(aws, settings, sid)
    assert statuses(receipt) == ["done"], receipt
    assert sid not in recycle_bin


def test_delete_snapshot_permanently(aws, settings):
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "delete_snapshot", snap)])
    receipt = actions.delete_snapshot_permanently(aws, settings, pid, sid)
    assert statuses(receipt) == ["done"]
    assert receipt["results"][0]["undo"] is None
    assert "IRREVERSIBLE" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_snapshots(Filters=[{"Name": "snapshot-id", "Values": [sid]}])["Snapshots"] == []


# ---------------------------------------------------------------- instances


def test_stop_then_start_instance(aws, settings):
    inst = make_instance(aws, {"Name": "idle-box"})
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])

    receipt = actions.stop_instances(aws, settings, pid, [iid])
    assert statuses(receipt) == ["done"], receipt
    assert receipt["results"][0]["undo"] == {"tool": "start_instances", "args": {"instance_ids": [iid]}}
    assert receipt["est_monthly_savings_usd"] == pytest.approx(round(0.0104 * 730, 2))
    desc = aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] in ("stopping", "stopped")
    assert TAG_STOPPED_AT in tags_to_dict(desc["Tags"])

    started = actions.start_instances(aws, settings, [iid])
    assert statuses(started) == ["done"], started
    desc = aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] in ("pending", "running")
    assert TAG_STOPPED_AT not in tags_to_dict(desc.get("Tags"))


def test_start_instances_refuses_untagged(aws, settings):
    inst = make_instance(aws)
    iid = inst["InstanceId"]
    aws.ec2.stop_instances(InstanceIds=[iid])
    receipt = actions.start_instances(aws, settings, [iid])
    assert statuses(receipt) == ["skipped"]
    assert "not stopped by Warden" in receipt["results"][0]["detail"]


def test_start_instances_batch_cap_and_wildcard(aws, settings):
    too_many = [f"i-{n:08x}" for n in range(settings.max_batch + 1)]
    assert "exceeds the limit" in actions.start_instances(aws, settings, too_many)["results"][0]["detail"]
    assert "wildcard" in actions.start_instances(aws, settings, ["*"])["results"][0]["detail"]


# ---------------------------------------------------------------- addresses


def test_release_address_records_ip(aws, settings):
    addr = make_address(aws)
    aid, ip = addr["AllocationId"], addr["PublicIp"]
    pid = make_plan(aws, settings, [("address", "release_address", addr)])

    receipt = actions.release_address(aws, settings, pid, aid)

    res = receipt["results"][0]
    assert res["status"] == "done", receipt
    assert res["public_ip"] == ip and res["undo"] is None
    assert "IRREVERSIBLE" in res["detail"] and f"allocate_address(Address='{ip}')" in res["detail"]
    assert receipt["est_monthly_savings_usd"] == pytest.approx(3.65)
    assert aws.ec2.describe_addresses()["Addresses"] == []


def test_release_address_associated_after_plan_skipped(aws, settings):
    addr = make_address(aws)
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    inst = make_instance(aws)
    aws.ec2.associate_address(AllocationId=addr["AllocationId"], InstanceId=inst["InstanceId"])

    receipt = actions.release_address(aws, settings, pid, addr["AllocationId"])
    assert statuses(receipt) == ["skipped"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 1


# ---------------------------------------------------------------- restore_volume


def test_restore_volume_recreates_with_original_tags_in_az(aws, settings):
    vol = make_volume(aws, {"Name": "db-scratch", "team": "data", "warden:demo": "true"}, vtype="gp3", size=12)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    snap_id = actions.quarantine_volumes(aws, settings, pid, [vid])["results"][0]["backup_snapshot_id"]

    receipt = actions.restore_volume(aws, settings, snap_id)

    assert statuses(receipt) == ["done"], receipt
    assert receipt["plan_id"] is None
    restored = aws.ec2.describe_volumes(Filters=[{"Name": f"tag:{TAG_RESTORED_FROM}", "Values": [snap_id]}])["Volumes"]
    assert len(restored) == 1
    new = restored[0]
    assert new["AvailabilityZone"] == AZ and new["VolumeType"] == "gp3" and new["Size"] == 12
    tags = tags_to_dict(new["Tags"])
    assert tags == {"Name": "db-scratch", "team": "data", "warden:demo": "true", TAG_RESTORED_FROM: snap_id}
    assert new["VolumeId"] in receipt["results"][0]["detail"]


def test_restore_volume_refuses_non_warden_snapshot(aws, settings):
    snap = make_snapshot(aws, {"Name": "someone-elses"})
    before = len(aws.ec2.describe_volumes()["Volumes"])
    receipt = actions.restore_volume(aws, settings, snap["SnapshotId"])
    assert statuses(receipt) == ["skipped"]
    assert "not a Warden backup" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_volumes()["Volumes"]) == before


def test_per_item_aws_error_becomes_failed(aws, settings, monkeypatch):
    inst = make_instance(aws)
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])

    def boom(**_):
        from botocore.exceptions import ClientError

        raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "no"}}, "StopInstances")

    monkeypatch.setattr(aws.ec2, "stop_instances", boom)
    receipt = actions.stop_instances(aws, settings, pid, [inst["InstanceId"]])
    assert statuses(receipt) == ["failed"]
    assert "UnauthorizedOperation" in receipt["results"][0]["detail"]


# ---------------------------------------------------------------- review fixes


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Retry/settle loops must not slow the suite down."""
    monkeypatch.setattr(actions, "_sleep", lambda seconds: None)


def _client_error(code: str, op: str = "Op"):
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": code, "Message": code}}, op)


def test_quarantine_total_wait_fits_mcp_timeout(aws, settings, monkeypatch):  # S1 / F2
    vols = [make_volume(aws), make_volume(aws)]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", v) for v in vols])
    clock = {"t": 1000.0}
    monkeypatch.setattr(actions, "_clock", lambda: clock["t"])
    configured: list[int] = []

    class SlowButDone:
        def wait(self, WaiterConfig, **_):
            configured.append(WaiterConfig["Delay"] * WaiterConfig["MaxAttempts"])
            clock["t"] += actions.CALL_BUDGET_SECONDS - 5  # the first snapshot eats the budget

    monkeypatch.setattr(aws.ec2, "get_waiter", lambda name: SlowButDone())
    receipt = actions.quarantine_volumes(aws, settings, pid, [v["VolumeId"] for v in vols])

    assert statuses(receipt) == ["done", "skipped"], receipt
    assert sum(configured) <= actions.CALL_BUDGET_SECONDS < 240
    assert "time budget" in receipt["results"][1]["detail"]
    assert aws.ec2.describe_volumes(VolumeIds=[vols[1]["VolumeId"]])["Volumes"]
    backups = aws.ec2.describe_snapshots(Filters=[{"Name": f"tag:{TAG_BACKUP_OF}", "Values": [vols[1]["VolumeId"]]}])
    assert backups["Snapshots"] == []  # nothing started for the item that did not fit


def test_quarantine_rerun_reuses_pending_backup(aws, settings, monkeypatch):  # S1: picked up on a re-run
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])

    class Pending:
        def wait(self, **_):
            raise WaiterError(name="SnapshotCompleted", reason="Max attempts exceeded", last_response={})

    monkeypatch.setattr(aws.ec2, "get_waiter", lambda name: Pending())
    first = actions.quarantine_volumes(aws, settings, pid, [vid])
    assert statuses(first) == ["skipped"]
    monkeypatch.undo()
    monkeypatch.setattr(actions, "_sleep", lambda seconds: None)
    second = actions.quarantine_volumes(aws, settings, pid, [vid])
    assert statuses(second) == ["done"], second
    assert second["results"][0]["backup_snapshot_id"] == first["results"][0]["backup_snapshot_id"]


def test_wait_retries_not_found_right_after_create():  # RA-2
    from warden.aws import wait_for

    calls: list[dict] = []

    class Waiter:
        def wait(self, **kw):
            calls.append(kw)
            if len(calls) == 1:
                raise WaiterError(
                    name="SnapshotCompleted", reason="An error occurred (InvalidSnapshot.NotFound)",
                    last_response={"Error": {"Code": "InvalidSnapshot.NotFound"}},
                )

    class Client:
        def get_waiter(self, name):
            assert name == "snapshot_completed"
            return Waiter()

    wait_for(Client(), "snapshot_completed", delay=5, max_attempts=10, sleep=lambda s: None, SnapshotIds=["snap-1"])
    assert len(calls) == 2 and calls[1]["SnapshotIds"] == ["snap-1"]
    assert calls[1]["WaiterConfig"]["MaxAttempts"] == 9


def test_wait_does_not_retry_other_errors():  # RA-2
    from warden.aws import wait_for

    class Waiter:
        def wait(self, **kw):
            raise WaiterError(name="VolumeAvailable", reason="terminal", last_response={"Volumes": []})

    class Client:
        def get_waiter(self, name):
            return Waiter()

    with pytest.raises(WaiterError):
        wait_for(Client(), "volume_available", delay=5, max_attempts=10, sleep=lambda s: None, VolumeIds=["v"])


def test_recycle_waits_for_tag_before_deleting(aws, settings, recycle_bin, monkeypatch):  # F3 / RA-4
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    real_describe = aws.ec2.describe_snapshots
    real_delete = aws.ec2.delete_snapshot
    seen = {"n": 0, "tag_visible_before_delete": False}

    def lagging_describe(**kw):  # right after tagging, the first read does not show the tag yet
        out = real_describe(**kw)
        seen["n"] += 1
        if seen["n"] == 2:
            for s in out["Snapshots"]:
                s["Tags"] = [t for t in s.get("Tags", []) if t["Key"] != TAG_RECYCLE]
        return out

    def delete(**kw):
        seen["tag_visible_before_delete"] = seen["n"] >= 3
        return real_delete(**kw)

    monkeypatch.setattr(aws.ec2, "describe_snapshots", lagging_describe)
    monkeypatch.setattr(aws.ec2, "delete_snapshot", delete)
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid])
    assert statuses(receipt) == ["done"], receipt
    assert seen["tag_visible_before_delete"]


def test_recycle_keeps_snapshot_when_tag_never_visible(aws, settings, recycle_bin, monkeypatch):  # F3
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    real_describe = aws.ec2.describe_snapshots
    calls = {"n": 0}

    def never_tagged(**kw):
        out = real_describe(**kw)
        calls["n"] += 1
        if calls["n"] > 1:  # the first read is the pre-action re-check
            for s in out["Snapshots"]:
                s["Tags"] = [t for t in s.get("Tags", []) if t["Key"] != TAG_RECYCLE]
        return out

    monkeypatch.setattr(aws.ec2, "describe_snapshots", never_tagged)
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid])
    assert statuses(receipt) == ["failed"]
    assert "not deleted" in receipt["results"][0]["detail"]
    assert sid not in recycle_bin
    assert real_describe(SnapshotIds=[sid])["Snapshots"]


def test_recycle_bin_listing_lag_is_retried(aws, settings, recycle_bin, monkeypatch):  # S4 / RA-4 / F3
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    real_list = aws.ec2.list_snapshots_in_recycle_bin
    polls = {"n": 0}

    def lagging(**kw):
        polls["n"] += 1
        return {"Snapshots": []} if polls["n"] < 3 else real_list(**kw)

    monkeypatch.setattr(aws.ec2, "list_snapshots_in_recycle_bin", lagging)
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid])
    assert statuses(receipt) == ["done"], receipt
    assert "verified" in receipt["results"][0]["detail"]


def test_recycle_verification_error_never_claims_recycle_bin(aws, settings, recycle_bin, monkeypatch):  # S4
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])

    def boom(**_):
        raise _client_error("InvalidSnapshot.NotFound", "ListSnapshotsInRecycleBin")

    monkeypatch.setattr(aws.ec2, "list_snapshots_in_recycle_bin", boom)
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid])
    detail = receipt["results"][0]["detail"]
    assert "moved to Recycle Bin" not in detail
    assert "NOT guaranteed" in detail


def test_restore_allowed_after_unverified_recycle(aws, settings, recycle_bin, monkeypatch):  # S4 / RA-4
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    real_list = aws.ec2.list_snapshots_in_recycle_bin
    monkeypatch.setattr(aws.ec2, "list_snapshots_in_recycle_bin", lambda **kw: {"Snapshots": []})
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid])
    assert statuses(receipt) == ["failed"]  # not seen in the bin (yet)
    monkeypatch.setattr(aws.ec2, "list_snapshots_in_recycle_bin", real_list)  # the bin catches up
    restored = actions.restore_snapshot(aws, settings, sid)
    assert statuses(restored) == ["done"], restored


def test_recycle_skips_snapshot_excluded_by_region_rule(aws, settings, recycle_bin, monkeypatch):  # S5
    snap = make_snapshot(aws, {"env": "dev"})
    rule = {"Status": "available", "RetentionPeriod": {"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
            "ExcludeResourceTags": [{"ResourceTagKey": "env", "ResourceTagValue": "dev"}]}
    monkeypatch.setattr(actions, "_recycle_rules", lambda clients: [rule])
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.recycle_snapshots(aws, settings, pid, [snap["SnapshotId"]])
    assert statuses(receipt) == ["skipped"]
    assert snap["SnapshotId"] not in recycle_bin
    assert aws.ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"]


def test_start_refuses_tagged_instance_without_warden_receipt(aws, settings):  # S7
    inst = make_instance(aws, {TAG_STOPPED_AT: "2026-01-01T00:00:00Z"})
    iid = inst["InstanceId"]
    aws.ec2.stop_instances(InstanceIds=[iid])
    receipt = actions.start_instances(aws, settings, [iid])
    assert statuses(receipt) == ["skipped"]
    assert "receipt" in receipt["results"][0]["detail"]


def test_start_refuses_out_of_scope_instance(aws, settings):  # S7
    inst = make_instance(aws, {"Name": "x"})
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])
    assert statuses(actions.stop_instances(aws, settings, pid, [iid])) == ["done"]
    scoped = dataclasses.replace(settings, scope_tag_key="warden:demo", scope_tag_value="true")
    receipt = actions.start_instances(aws, scoped, [iid])
    assert statuses(receipt) == ["skipped"]
    assert "scope" in receipt["results"][0]["detail"]


def test_restore_volume_refuses_out_of_scope_backup(aws, settings):  # S7
    vol = make_volume(aws, {"Name": "x"})
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    snap_id = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]])["results"][0]["backup_snapshot_id"]
    scoped = dataclasses.replace(settings, scope_tag_key="warden:demo", scope_tag_value="true")
    receipt = actions.restore_volume(aws, scoped, snap_id)
    assert statuses(receipt) == ["skipped"]
    assert "scope" in receipt["results"][0]["detail"]


def test_stop_rechecks_activity_before_stopping(aws, settings, monkeypatch):  # S8
    from warden import scanner

    inst = make_instance(aws)
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])
    monkeypatch.setattr(scanner, "BOOT_WARMUP_MINUTES", -60)  # moto launched it just now

    def busy(**kw):
        stat = kw["Statistics"][0]
        return {"Datapoints": [{stat: 90.0 if kw["MetricName"] == "CPUUtilization" else 10.0}]}

    monkeypatch.setattr(aws.cloudwatch, "get_metric_statistics", busy)
    receipt = actions.stop_instances(aws, settings, pid, [iid])
    assert statuses(receipt) == ["skipped"]
    assert "active" in receipt["results"][0]["detail"]
    desc = aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] == "running"


def test_freeze_file_blocks_without_restart(aws, settings):  # S14
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    (settings.state_dir / "FREEZE").write_text("", encoding="utf-8")
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]])
    assert statuses(receipt) == ["skipped"] and receipt["freeze"] is True
    assert statuses(actions.start_instances(aws, settings, ["i-12345678"])) == ["skipped"]
    assert aws.ec2.describe_volumes(VolumeIds=[vol["VolumeId"]])["Volumes"]


def test_release_is_done_even_if_describe_lags(aws, settings, monkeypatch):  # RA-3 (a)
    addr = make_address(aws)
    aid = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    real_describe = aws.ec2.describe_addresses
    real_release = aws.ec2.release_address
    stale = {"on": False}

    def release(**kw):
        out = real_release(**kw)
        stale["on"] = True
        return out

    monkeypatch.setattr(aws.ec2, "release_address", release)
    monkeypatch.setattr(aws.ec2, "describe_addresses",
                        lambda **kw: {"Addresses": [addr]} if stale["on"] else real_describe(**kw))
    receipt = actions.release_address(aws, settings, pid, aid)
    assert statuses(receipt) == ["done"], receipt
    assert "IRREVERSIBLE" in receipt["results"][0]["detail"]


def test_delete_snapshot_is_done_even_if_describe_lags(aws, settings, monkeypatch):  # RA-3 (b)
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "delete_snapshot", snap)])
    real_describe = aws.ec2.describe_snapshots
    real_delete = aws.ec2.delete_snapshot
    stale = {"on": False}

    def delete(**kw):
        out = real_delete(**kw)
        stale["on"] = True
        return out

    monkeypatch.setattr(aws.ec2, "delete_snapshot", delete)
    monkeypatch.setattr(aws.ec2, "describe_snapshots",
                        lambda **kw: {"Snapshots": [snap]} if stale["on"] else real_describe(**kw))
    receipt = actions.delete_snapshot_permanently(aws, settings, pid, sid)
    assert statuses(receipt) == ["done"], receipt


def test_stop_and_start_trust_the_api_response(aws, settings, monkeypatch):  # RA-3 (c, d)
    inst = make_instance(aws)
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])
    real_describe = aws.ec2.describe_instances
    stale_view = {"state": None}

    def stale_describe(**kw):
        out = real_describe(**kw)
        if stale_view["state"]:
            for r in out["Reservations"]:
                for i in r["Instances"]:
                    i["State"] = {"Name": stale_view["state"], "Code": 0}
        return out

    real_stop = aws.ec2.stop_instances

    def stop(**kw):
        out = real_stop(**kw)
        stale_view["state"] = "running"  # stale read right after the stop
        return out

    monkeypatch.setattr(aws.ec2, "describe_instances", stale_describe)
    monkeypatch.setattr(aws.ec2, "stop_instances", stop)
    assert statuses(actions.stop_instances(aws, settings, pid, [iid])) == ["done"]

    stale_view["state"] = None
    real_start = aws.ec2.start_instances

    def start(**kw):
        out = real_start(**kw)
        stale_view["state"] = "stopped"  # stale read right after the start
        return out

    monkeypatch.setattr(aws.ec2, "start_instances", start)
    started = actions.start_instances(aws, settings, [iid])
    assert statuses(started) == ["done"], started


def test_restore_volume_done_even_if_new_volume_not_yet_describable(aws, settings, monkeypatch):  # RA-3 (e)
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    snap_id = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]])["results"][0]["backup_snapshot_id"]

    def not_yet(**_):
        raise _client_error("InvalidVolume.NotFound", "DescribeVolumes")

    monkeypatch.setattr(aws.ec2, "describe_volumes", not_yet)
    receipt = actions.restore_volume(aws, settings, snap_id)
    assert statuses(receipt) == ["done"], receipt
