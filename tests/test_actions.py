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

    monkeypatch.setattr(actions, "_recycle_bin_ready", lambda clients: True)
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
    monkeypatch.setattr(actions, "_recycle_bin_ready", lambda clients: False)
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.recycle_snapshots(aws, settings, pid, [snap["SnapshotId"]])
    assert statuses(receipt) == ["skipped"]
    assert "Recycle Bin rule missing" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"]


def test_recycle_verification_unavailable_degrades(aws, settings, monkeypatch):
    snap = make_snapshot(aws)
    monkeypatch.setattr(actions, "_recycle_bin_ready", lambda clients: True)
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
