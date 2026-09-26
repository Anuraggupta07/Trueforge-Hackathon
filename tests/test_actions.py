"""Tests for warden.actions (moto-backed; plans are built directly, not via the scanner)."""

from __future__ import annotations

import dataclasses
import importlib
import json
import sys
import time
import types

import pytest
from botocore.exceptions import WaiterError

from warden import actions, audit
from warden import plan as plan_mod
from warden.config import (
    TAG_BACKUP_OF,
    TAG_EXPIRES_AT,
    TAG_HUMAN_UNDO_AT,
    TAG_PLAN_ID,
    TAG_QUARANTINED_AT,
    TAG_QUARANTINED_UNTIL,
    TAG_RECYCLE,
    TAG_RESTORE_AZ,
    TAG_RESTORED_FROM,
    TAG_STOPPED_AT,
)
from warden.policy import tags_to_dict

AZ = "us-east-1b"
AMI = "ami-12c6146b"
SIG = "wd-test-ok.sig"
QUARANTINE_OVER = {TAG_QUARANTINED_AT: "1999-12-25T00:00:00Z", TAG_QUARANTINED_UNTIL: "2000-01-01T00:00:00Z"}
QUARANTINE_ACTIVE = {TAG_QUARANTINED_UNTIL: "2999-01-01T00:00:00Z"}


# ---------------------------------------------------------------- watchdog stub


def install_watchdog_stub(monkeypatch, verdict=None) -> list[tuple]:
    """Replace warden.watchdog.check_signoff (the real module may not exist yet) so these tests only
    exercise the executor. Accepts SIG unless verdict says otherwise; returns the recorded calls."""
    try:
        module = importlib.import_module("warden.watchdog")
    except Exception:  # noqa: BLE001 - module missing or mid-edit
        module = types.ModuleType("warden.watchdog")
        monkeypatch.setitem(sys.modules, "warden.watchdog", module)
        import warden

        monkeypatch.setattr(warden, "watchdog", module, raising=False)
    calls: list[tuple] = []

    def check_signoff(settings, token, plan_id, action, resource_ids, now=None):
        calls.append((token, plan_id, action, list(resource_ids)))
        if verdict is not None:
            return verdict
        return (True, "", {}) if token == SIG else (False, "HMAC mismatch", {})

    monkeypatch.setattr(module, "check_signoff", check_signoff, raising=False)
    return calls


@pytest.fixture(autouse=True)
def watchdog_calls(monkeypatch):
    return install_watchdog_stub(monkeypatch)


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


def make_quarantined_address(aws, settings) -> dict:
    """An Elastic IP whose Warden quarantine (tags + a receipt recording the same window) ended in the past."""
    addr = make_address(aws, QUARANTINE_OVER)
    audit.save_receipt(settings, {
        "receipt_id": audit.new_id("rcpt"), "action": "quarantine_address", "plan_id": "plan-x",
        "finished_at": QUARANTINE_OVER[TAG_QUARANTINED_AT],
        "results": [{"resource_id": addr["AllocationId"], "status": "done",
                     "quarantined_at": QUARANTINE_OVER[TAG_QUARANTINED_AT],
                     "quarantined_until": QUARANTINE_OVER[TAG_QUARANTINED_UNTIL]}],
    })
    return addr


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

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)

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
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=SIG)

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
    receipt = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)

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

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)

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

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)

    res = receipt["results"][0]
    assert res["status"] == "skipped"
    assert "changed since approval" in res["detail"] and "production" in res["detail"]
    assert aws.ec2.describe_volumes(VolumeIds=[vid])["Volumes"]


def test_innocent_tag_change_is_fingerprint_drift(aws, settings):
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    aws.ec2.create_tags(Resources=[vid], Tags=[{"Key": "owner", "Value": "alice"}])

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "changed since approval" in receipt["results"][0]["detail"]


def test_volume_gone_is_skipped(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    aws.ec2.delete_volume(VolumeId=vol["VolumeId"])

    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=SIG)
    assert receipt["results"][0]["detail"] == "no longer exists"


def test_scope_tag_removed_after_plan_is_skipped(aws, settings):
    scoped = dataclasses.replace(settings, scope_tag_key="warden:demo", scope_tag_value="true")
    vol = make_volume(aws, {"warden:demo": "true"})
    vid = vol["VolumeId"]
    pid = make_plan(aws, scoped, [("volume", "quarantine_volume", vol)])
    aws.ec2.delete_tags(Resources=[vid], Tags=[{"Key": "warden:demo"}])

    receipt = actions.quarantine_volumes(aws, scoped, pid, [vid], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "no longer in scope" in receipt["results"][0]["detail"]


# ---------------------------------------------------------------- request-level guards


def test_freeze_refuses_everything(aws, settings):
    frozen = dataclasses.replace(settings, freeze=True)
    vol = make_volume(aws)
    pid = make_plan(aws, frozen, [("volume", "quarantine_volume", vol)])

    receipt = actions.quarantine_volumes(aws, frozen, pid, [vol["VolumeId"]], signoff=SIG)

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
    receipt = actions.quarantine_volumes(aws, settings, "plan-does-not-exist", [vol["VolumeId"]], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "not found" in receipt["results"][0]["detail"]


def test_id_not_in_plan_rejected(aws, settings):
    planned, other = make_volume(aws), make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", planned)])

    receipt = actions.quarantine_volumes(aws, settings, pid, [other["VolumeId"]], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "not in plan" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_volumes(VolumeIds=[other["VolumeId"]])["Volumes"]


def test_keep_verdict_rejected(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)], verdict="keep")
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=SIG)
    assert "not 'act'" in receipt["results"][0]["detail"]


def test_expired_plan(aws, settings):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)], now=time.time() - 2 * 3600)
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "expired" in receipt["results"][0]["detail"]


def test_batch_over_cap(aws, settings):
    vols = [make_volume(aws) for _ in range(settings.max_batch + 1)]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", v) for v in vols])
    receipt = actions.quarantine_volumes(aws, settings, pid, [v["VolumeId"] for v in vols], signoff=SIG)
    assert statuses(receipt) == ["skipped"] * len(vols)
    assert "exceeds the limit" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_volumes()["Volumes"]) == len(vols)


@pytest.mark.parametrize("ids", [[], ["*"], ["all"], ["vol-*"]])
def test_empty_and_wildcard_rejected(aws, settings, ids):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    receipt = actions.quarantine_volumes(aws, settings, pid, ids, signoff=SIG)
    assert receipt["counts"]["done"] == 0
    assert set(statuses(receipt)) == {"skipped"}


def test_irreversible_with_two_ids_rejected(aws, settings):
    a, b = make_address(aws), make_address(aws)
    pid = make_plan(aws, settings, [("address", "release_address", a), ("address", "release_address", b)])
    ids = [a["AllocationId"], b["AllocationId"]]
    # Bypass the single-id signature to prove the gate itself enforces it.
    receipt = actions._run_gated(aws, settings, "release_address", pid, ids, actions._release_one, signoff=SIG)
    assert statuses(receipt) == ["skipped", "skipped"]
    assert "exactly one id" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 2


def test_wrong_action_for_plan_item(aws, settings):
    snap = make_snapshot(aws)
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.delete_snapshot_permanently(aws, settings, pid, snap["SnapshotId"], signoff=SIG)
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
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid], signoff=SIG)

    assert statuses(receipt) == ["done"], receipt
    assert "verified" in receipt["results"][0]["detail"]
    assert receipt["results"][0]["undo"] == {"tool": "restore_snapshot", "args": {"snapshot_id": sid}}
    assert {"Key": TAG_RECYCLE, "Value": "true"} in tagged[0]["Tags"]
    assert sid in recycle_bin


def test_recycle_refused_without_recycle_bin_rule(aws, settings, monkeypatch):
    snap = make_snapshot(aws)
    monkeypatch.setattr(actions, "_recycle_rules", lambda clients: [])
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.recycle_snapshots(aws, settings, pid, [snap["SnapshotId"]], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "Recycle Bin rule missing" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"]


def test_recycle_verification_unavailable_degrades(aws, settings, monkeypatch):
    snap = make_snapshot(aws)
    monkeypatch.setattr(actions, "_recycle_rules", lambda clients: [WARDEN_RULE])
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    receipt = actions.recycle_snapshots(aws, settings, pid, [snap["SnapshotId"]], signoff=SIG)
    assert statuses(receipt) == ["done"]
    assert "verification unavailable" in receipt["results"][0]["detail"]


def test_restore_snapshot_only_if_warden_recycled(aws, settings, recycle_bin):
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    assert "not recycled by Warden" in actions.restore_snapshot(aws, settings, sid)["results"][0]["detail"]

    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    assert statuses(actions.recycle_snapshots(aws, settings, pid, [sid], signoff=SIG)) == ["done"]
    receipt = actions.restore_snapshot(aws, settings, sid)
    assert statuses(receipt) == ["done"], receipt
    assert sid not in recycle_bin


def test_delete_snapshot_permanently(aws, settings):
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "delete_snapshot", snap)])
    receipt = actions.delete_snapshot_permanently(aws, settings, pid, sid, signoff=SIG)
    assert statuses(receipt) == ["done"]
    assert receipt["results"][0]["undo"] is None
    assert "IRREVERSIBLE" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_snapshots(Filters=[{"Name": "snapshot-id", "Values": [sid]}])["Snapshots"] == []


# ---------------------------------------------------------------- instances


def test_stop_then_start_instance(aws, settings):
    inst = make_instance(aws, {"Name": "idle-box"})
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])

    receipt = actions.stop_instances(aws, settings, pid, [iid], signoff=SIG)
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
    addr = make_quarantined_address(aws, settings)
    aid, ip = addr["AllocationId"], addr["PublicIp"]
    pid = make_plan(aws, settings, [("address", "release_address", addr)])

    receipt = actions.release_address(aws, settings, pid, aid, signoff=SIG)

    res = receipt["results"][0]
    assert res["status"] == "done", receipt
    assert res["public_ip"] == ip and res["undo"] is None
    assert "IRREVERSIBLE" in res["detail"] and f"allocate_address(Address='{ip}')" in res["detail"]
    assert receipt["est_monthly_savings_usd"] == pytest.approx(3.65)
    assert aws.ec2.describe_addresses()["Addresses"] == []


def test_release_address_associated_after_plan_skipped(aws, settings):
    addr = make_quarantined_address(aws, settings)
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    inst = make_instance(aws)
    aws.ec2.associate_address(AllocationId=addr["AllocationId"], InstanceId=inst["InstanceId"])

    receipt = actions.release_address(aws, settings, pid, addr["AllocationId"], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 1


# ---------------------------------------------------------------- restore_volume


def test_restore_volume_recreates_with_original_tags_in_az(aws, settings):
    vol = make_volume(aws, {"Name": "db-scratch", "team": "data", "warden:demo": "true"}, vtype="gp3", size=12)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    snap_id = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)["results"][0]["backup_snapshot_id"]

    receipt = actions.restore_volume(aws, settings, snap_id)

    assert statuses(receipt) == ["done"], receipt
    assert receipt["plan_id"] is None
    restored = aws.ec2.describe_volumes(Filters=[{"Name": f"tag:{TAG_RESTORED_FROM}", "Values": [snap_id]}])["Volumes"]
    assert len(restored) == 1
    new = restored[0]
    assert new["AvailabilityZone"] == AZ and new["VolumeType"] == "gp3" and new["Size"] == 12
    tags = tags_to_dict(new["Tags"])
    undo_at = tags.pop(TAG_HUMAN_UNDO_AT)  # a human undid this: later scans leave it alone
    assert actions._parse_utc(undo_at) is not None
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
    receipt = actions.stop_instances(aws, settings, pid, [inst["InstanceId"]], signoff=SIG)
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
    receipt = actions.quarantine_volumes(aws, settings, pid, [v["VolumeId"] for v in vols], signoff=SIG)

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
    first = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)
    assert statuses(first) == ["skipped"]
    monkeypatch.undo()
    monkeypatch.setattr(actions, "_sleep", lambda seconds: None)
    install_watchdog_stub(monkeypatch)
    second = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)
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
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid], signoff=SIG)
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
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid], signoff=SIG)
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
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid], signoff=SIG)
    assert statuses(receipt) == ["done"], receipt
    assert "verified" in receipt["results"][0]["detail"]


def test_recycle_verification_error_never_claims_recycle_bin(aws, settings, recycle_bin, monkeypatch):  # S4
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])

    def boom(**_):
        raise _client_error("InvalidSnapshot.NotFound", "ListSnapshotsInRecycleBin")

    monkeypatch.setattr(aws.ec2, "list_snapshots_in_recycle_bin", boom)
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid], signoff=SIG)
    detail = receipt["results"][0]["detail"]
    assert "moved to Recycle Bin" not in detail
    assert "NOT guaranteed" in detail


def test_restore_allowed_after_unverified_recycle(aws, settings, recycle_bin, monkeypatch):  # S4 / RA-4
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    real_list = aws.ec2.list_snapshots_in_recycle_bin
    monkeypatch.setattr(aws.ec2, "list_snapshots_in_recycle_bin", lambda **kw: {"Snapshots": []})
    receipt = actions.recycle_snapshots(aws, settings, pid, [sid], signoff=SIG)
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
    receipt = actions.recycle_snapshots(aws, settings, pid, [snap["SnapshotId"]], signoff=SIG)
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
    assert statuses(actions.stop_instances(aws, settings, pid, [iid], signoff=SIG)) == ["done"]
    scoped = dataclasses.replace(settings, scope_tag_key="warden:demo", scope_tag_value="true")
    receipt = actions.start_instances(aws, scoped, [iid])
    assert statuses(receipt) == ["skipped"]
    assert "scope" in receipt["results"][0]["detail"]


def test_restore_volume_refuses_out_of_scope_backup(aws, settings):  # S7
    vol = make_volume(aws, {"Name": "x"})
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=SIG)
    snap_id = receipt["results"][0]["backup_snapshot_id"]
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
    receipt = actions.stop_instances(aws, settings, pid, [iid], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "active" in receipt["results"][0]["detail"]
    desc = aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] == "running"


def test_freeze_file_blocks_without_restart(aws, settings):  # S14
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    (settings.state_dir / "FREEZE").write_text("", encoding="utf-8")
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=SIG)
    assert statuses(receipt) == ["skipped"] and receipt["freeze"] is True
    assert statuses(actions.start_instances(aws, settings, ["i-12345678"])) == ["skipped"]
    assert aws.ec2.describe_volumes(VolumeIds=[vol["VolumeId"]])["Volumes"]


def test_release_is_done_even_if_describe_lags(aws, settings, monkeypatch):  # RA-3 (a)
    addr = make_quarantined_address(aws, settings)
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
    receipt = actions.release_address(aws, settings, pid, aid, signoff=SIG)
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
    receipt = actions.delete_snapshot_permanently(aws, settings, pid, sid, signoff=SIG)
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
    assert statuses(actions.stop_instances(aws, settings, pid, [iid], signoff=SIG)) == ["done"]

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
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=SIG)
    snap_id = receipt["results"][0]["backup_snapshot_id"]

    def not_yet(**_):
        raise _client_error("InvalidVolume.NotFound", "DescribeVolumes")

    monkeypatch.setattr(aws.ec2, "describe_volumes", not_yet)
    receipt = actions.restore_volume(aws, settings, snap_id)
    assert statuses(receipt) == ["done"], receipt


# ---------------------------------------------------------------- watchdog sign-off gate (v1.1)


@pytest.mark.parametrize("token", [None, "", "   "])
def test_missing_signoff_skips_everything(aws, settings, watchdog_calls, token):
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=token)
    assert statuses(receipt) == ["skipped"]
    detail = receipt["results"][0]["detail"]
    assert detail.startswith("Watchdog sign-off rejected: missing sign-off token")
    assert "call watchdog_verify first" in detail
    assert watchdog_calls == []
    assert aws.ec2.describe_volumes(VolumeIds=[vol["VolumeId"]])["Volumes"][0]["State"] == "available"
    backups = aws.ec2.describe_snapshots(Filters=[{"Name": f"tag:{TAG_BACKUP_OF}", "Values": [vol["VolumeId"]]}])
    assert backups["Snapshots"] == []


def test_signoff_is_required_keyword(aws, settings):
    with pytest.raises(TypeError):
        actions.stop_instances(aws, settings, "plan-x", ["i-12345678"])  # type: ignore[call-arg]


def test_rejected_signoff_skips_everything_and_mutates_nothing(aws, settings, watchdog_calls):
    insts = [make_instance(aws), make_instance(aws)]
    ids = [i["InstanceId"] for i in insts]
    pid = make_plan(aws, settings, [("instance", "stop_instance", i) for i in insts])

    receipt = actions.stop_instances(aws, settings, pid, ids, signoff="wd-forged.deadbeef")

    assert statuses(receipt) == ["skipped", "skipped"]
    for r in receipt["results"]:
        assert r["detail"] == "Watchdog sign-off rejected: HMAC mismatch - call watchdog_verify first"
    assert watchdog_calls == [("wd-forged.deadbeef", pid, "stop_instance", ids)]
    for iid in ids:
        desc = aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        assert desc["State"]["Name"] == "running"
        assert TAG_STOPPED_AT not in tags_to_dict(desc.get("Tags"))


@pytest.mark.parametrize("reason", ["expired", "already consumed", "plan/action mismatch"])
def test_every_rejection_reason_is_reported(aws, settings, monkeypatch, reason):
    install_watchdog_stub(monkeypatch, verdict=(False, reason, {}))
    snap = make_snapshot(aws)
    pid = make_plan(aws, settings, [("snapshot", "delete_snapshot", snap)])
    receipt = actions.delete_snapshot_permanently(aws, settings, pid, snap["SnapshotId"], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert reason in receipt["results"][0]["detail"]
    assert aws.ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"]


def test_watchdog_error_is_a_rejection(aws, settings, monkeypatch):
    install_watchdog_stub(monkeypatch)
    wd = sys.modules["warden.watchdog"]

    def boom(*a, **k):
        raise RuntimeError("key file unreadable")

    monkeypatch.setattr(wd, "check_signoff", boom)
    vol = make_volume(aws)
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    receipt = actions.quarantine_volumes(aws, settings, pid, [vol["VolumeId"]], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "could not be checked" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_volumes(VolumeIds=[vol["VolumeId"]])["Volumes"]


def test_freeze_wins_before_signoff(aws, settings, watchdog_calls):
    frozen = dataclasses.replace(settings, freeze=True)
    receipt = actions.stop_instances(aws, frozen, "plan-x", ["i-12345678"], signoff="bogus")
    assert receipt["results"][0]["detail"] == actions.FROZEN_DETAIL
    assert watchdog_calls == []


def test_signed_fingerprint_must_match_plan(aws, settings, monkeypatch):
    inst = make_instance(aws)
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])
    install_watchdog_stub(monkeypatch, verdict=(True, "", {iid: "some-other-fingerprint"}))
    receipt = actions.stop_instances(aws, settings, pid, [iid], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "different state" in receipt["results"][0]["detail"]


def test_executor_keeps_its_own_recheck_after_signoff(aws, settings):  # defence in depth
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    aws.ec2.create_tags(Resources=[vid], Tags=[{"Key": "Env", "Value": "Production"}])
    receipt = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "production" in receipt["results"][0]["detail"]


# ---------------------------------------------------------------- EIP quarantine-before-release


def _addr_tags(aws, aid: str) -> dict[str, str]:
    return tags_to_dict(aws.ec2.describe_addresses(AllocationIds=[aid])["Addresses"][0].get("Tags"))


def test_quarantine_addresses_tags_and_receipt(aws, settings, watchdog_calls):
    addr = make_address(aws, {"Name": "old-ip"})
    aid, ip = addr["AllocationId"], addr["PublicIp"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])

    before = time.time()
    receipt = actions.quarantine_addresses(aws, settings, pid, [aid], signoff=SIG)

    assert statuses(receipt) == ["done"], receipt
    res = receipt["results"][0]
    assert res["undo"] == {"tool": "cancel_address_quarantine", "args": {"allocation_id": aid}}
    assert res["public_ip"] == ip and "quarantined" in res["detail"]
    assert receipt["action"] == "quarantine_address" and receipt["est_monthly_savings_usd"] == 0.0
    assert watchdog_calls == [(SIG, pid, "quarantine_address", [aid])]
    tags = _addr_tags(aws, aid)
    assert tags[TAG_PLAN_ID] == pid and TAG_QUARANTINED_AT in tags
    until = actions._parse_utc(tags[TAG_QUARANTINED_UNTIL]).timestamp()
    expected = before + settings.quarantine_minutes * 60
    assert expected - 5 <= until <= expected + 65
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 1  # nothing released


def test_quarantine_addresses_skips_associated(aws, settings):
    addr = make_address(aws)
    aid = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    inst = make_instance(aws)
    aws.ec2.associate_address(AllocationId=aid, InstanceId=inst["InstanceId"])
    receipt = actions.quarantine_addresses(aws, settings, pid, [aid], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert TAG_QUARANTINED_UNTIL not in _addr_tags(aws, aid)


def test_quarantine_addresses_requires_signoff(aws, settings):
    addr = make_address(aws)
    aid = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    receipt = actions.quarantine_addresses(aws, settings, pid, [aid], signoff="nope")
    assert statuses(receipt) == ["skipped"]
    assert TAG_QUARANTINED_UNTIL not in _addr_tags(aws, aid)


def test_cancel_address_quarantine_removes_tags(aws, settings):
    addr = make_address(aws, {"Name": "keep-me"})
    aid = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    assert statuses(actions.quarantine_addresses(aws, settings, pid, [aid], signoff=SIG)) == ["done"]

    receipt = actions.cancel_address_quarantine(aws, settings, aid)

    assert statuses(receipt) == ["done"], receipt
    assert receipt["plan_id"] is None and receipt["action"] == "cancel_address_quarantine"
    tags = _addr_tags(aws, aid)
    assert actions._parse_utc(tags.pop(TAG_HUMAN_UNDO_AT)) is not None  # a human kept it: later scans leave it alone
    assert tags == {"Name": "keep-me"}


def test_cancel_address_quarantine_refuses_untagged(aws, settings):
    addr = make_address(aws, {"Name": "never-quarantined"})
    receipt = actions.cancel_address_quarantine(aws, settings, addr["AllocationId"])
    assert statuses(receipt) == ["skipped"]
    assert "not quarantined by Warden" in receipt["results"][0]["detail"]
    assert _addr_tags(aws, addr["AllocationId"]) == {"Name": "never-quarantined"}


def test_cancel_address_quarantine_frozen(aws, settings):
    frozen = dataclasses.replace(settings, freeze=True)
    addr = make_address(aws, QUARANTINE_ACTIVE)
    receipt = actions.cancel_address_quarantine(aws, frozen, addr["AllocationId"])
    assert receipt["results"][0]["detail"] == actions.FROZEN_DETAIL
    assert TAG_QUARANTINED_UNTIL in _addr_tags(aws, addr["AllocationId"])


def test_release_refused_when_never_quarantined(aws, settings):
    addr = make_address(aws)
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    receipt = actions.release_address(aws, settings, pid, addr["AllocationId"], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "must be quarantined first" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 1


def test_release_refused_inside_quarantine_window(aws, settings):
    addr = make_address(aws, QUARANTINE_ACTIVE)
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    receipt = actions.release_address(aws, settings, pid, addr["AllocationId"], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert "still in quarantine until 2999-01-01T00:00:00Z" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 1


def test_quarantine_then_release_after_window(aws, settings, clock):
    fast = dataclasses.replace(settings, quarantine_minutes=1)
    addr = make_address(aws)
    aid = addr["AllocationId"]
    pid = make_plan(aws, fast, [("address", "quarantine_address", addr)])
    assert statuses(actions.quarantine_addresses(aws, fast, pid, [aid], signoff=SIG)) == ["done"]

    quarantined = aws.ec2.describe_addresses(AllocationIds=[aid])["Addresses"][0]
    pid2 = make_plan(aws, fast, [("address", "release_address", quarantined)])
    early = actions.release_address(aws, fast, pid2, aid, signoff=SIG)
    assert statuses(early) == ["skipped"] and "still in quarantine" in early["results"][0]["detail"]

    # The window really passes (the clock moves; tags and receipt are untouched), then a fresh plan.
    clock.advance(2 * 60)
    expired = aws.ec2.describe_addresses(AllocationIds=[aid])["Addresses"][0]
    pid3 = make_plan(aws, fast, [("address", "release_address", expired)])
    receipt = actions.release_address(aws, fast, pid3, aid, signoff=SIG)
    assert statuses(receipt) == ["done"], receipt
    assert "IRREVERSIBLE" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_addresses()["Addresses"] == []


def test_release_refused_when_quarantine_until_tag_moved_into_the_past(aws, settings):  # tags are mutable
    addr = make_address(aws)
    aid = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    res = actions.quarantine_addresses(aws, settings, pid, [aid], signoff=SIG)["results"][0]
    assert res["status"] == "done"

    # Someone edits the tag to end the window early; Warden's receipt still records the real window.
    aws.ec2.create_tags(Resources=[aid], Tags=[{"Key": TAG_QUARANTINED_UNTIL, "Value": "2000-01-01T00:00:00Z"}])
    tampered = aws.ec2.describe_addresses(AllocationIds=[aid])["Addresses"][0]
    pid2 = make_plan(aws, settings, [("address", "release_address", tampered)])
    receipt = actions.release_address(aws, settings, pid2, aid, signoff=SIG)
    assert statuses(receipt) == ["skipped"], receipt
    assert "tags were changed" in receipt["results"][0]["detail"]
    assert res["quarantined_until"] in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 1


# ---------------------------------------------------------------- review fixes


def test_release_refused_without_warden_quarantine_receipt(aws, settings):  # bypass F1
    addr = make_address(aws, QUARANTINE_OVER)  # tags look right, but Warden never quarantined it
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    receipt = actions.release_address(aws, settings, pid, addr["AllocationId"], signoff=SIG)
    assert statuses(receipt) == ["skipped"] and "not set by Warden" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 1


def test_release_refused_when_quarantine_was_voided(aws, settings):  # bypass F1 / demo F2
    addr = make_quarantined_address(aws, settings)
    aid = addr["AllocationId"]
    audit.record_quarantine_void(settings, aid, tags_to_dict(addr["Tags"]), "seen associated")
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    receipt = actions.release_address(aws, settings, pid, aid, signoff=SIG)
    assert statuses(receipt) == ["skipped"] and "void" in receipt["results"][0]["detail"]
    assert len(aws.ec2.describe_addresses()["Addresses"]) == 1


def test_quarantine_receipt_records_the_window(aws, settings):  # bypass F1: release binds to this record
    addr = make_address(aws)
    aid = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    res = actions.quarantine_addresses(aws, settings, pid, [aid], signoff=SIG)["results"][0]
    tags = _addr_tags(aws, aid)
    assert res["quarantined_at"] == tags[TAG_QUARANTINED_AT]
    assert res["quarantined_until"] == tags[TAG_QUARANTINED_UNTIL]


def test_release_rechecks_dns_right_before_releasing(aws, settings, monkeypatch):  # bypass F4
    from warden import scanner

    addr = make_quarantined_address(aws, settings)
    ip = addr["PublicIp"]
    pid = make_plan(aws, settings, [("address", "release_address", addr)])
    monkeypatch.setattr(scanner, "dns_references",
                        lambda clients, public_ip, **kw: ["shop.example.com (A) in zone example.com"])
    receipt = actions.release_address(aws, settings, pid, addr["AllocationId"], signoff=SIG)
    assert statuses(receipt) == ["skipped"] and "shop.example.com" in receipt["results"][0]["detail"]

    def down(clients, public_ip, **kw):
        assert kw.get("strict") is True
        raise RuntimeError("route53 down")

    monkeypatch.setattr(scanner, "dns_references", down)
    receipt = actions.release_address(aws, settings, pid, addr["AllocationId"], signoff=SIG)
    assert statuses(receipt) == ["skipped"] and "could not check DNS" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_addresses(AllocationIds=[addr["AllocationId"]])["Addresses"][0]["PublicIp"] == ip


def test_delete_snapshot_rechecks_ami_use_right_before_deleting(aws, settings, monkeypatch):  # bypass F4
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "delete_snapshot", snap)])
    image = {"ImageId": "ami-new", "BlockDeviceMappings": [{"Ebs": {"SnapshotId": sid}}]}
    monkeypatch.setattr(aws.ec2, "describe_images", lambda **kw: {"Images": [image]})
    receipt = actions.delete_snapshot_permanently(aws, settings, pid, sid, signoff=SIG)
    assert statuses(receipt) == ["skipped"] and "ami-new" in receipt["results"][0]["detail"]
    assert aws.ec2.describe_snapshots(SnapshotIds=[sid])["Snapshots"]


def test_restore_volume_is_in_the_source_volume_history(aws, settings):  # demo F3
    vol = make_volume(aws, {"Name": "db-scratch"})
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    snap_id = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)["results"][0]["backup_snapshot_id"]
    res = actions.restore_volume(aws, settings, snap_id)["results"][0]
    assert res["status"] == "done" and res["restored_volume_id"].startswith("vol-")
    latest = audit.history(settings, vid)[0]
    assert latest["event"] == "action_item" and latest["action"] == "restore_volume"
    assert res["restored_volume_id"] in latest["resource_ids"]


# ---------------------------------------------------------------- confirmed review findings (trust layer)


def _quarantined_backup(aws, settings, tags: dict[str, str] | None = None) -> tuple[str, str]:
    """(volume id, backup snapshot id) of a volume Warden quarantined for real."""
    vol = make_volume(aws, tags or {"Name": "db-scratch"})
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    res = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)["results"][0]
    assert res["status"] == "done", res
    return vid, res["backup_snapshot_id"]


def _restored_from(aws, snap_id: str) -> list[dict]:
    vols = aws.ec2.describe_volumes(Filters=[{"Name": f"tag:{TAG_RESTORED_FROM}", "Values": [snap_id]}])["Volumes"]
    return [v for v in vols if v["State"] not in ("deleting", "deleted")]


def test_restore_volume_twice_does_not_duplicate(aws, settings, monkeypatch):  # finding 20 / 5
    _, snap_id = _quarantined_backup(aws, settings)
    first = actions.restore_volume(aws, settings, snap_id)
    assert statuses(first) == ["done"], first
    new_vol = first["results"][0]["restored_volume_id"]
    creates: list[dict] = []
    real_create = aws.ec2.create_volume
    monkeypatch.setattr(aws.ec2, "create_volume", lambda **kw: creates.append(kw) or real_create(**kw))

    again = actions.restore_volume(aws, settings, snap_id)  # a retry, or an old receipt's Undo button

    assert statuses(again) == ["skipped"], again
    assert f"already restored as {new_vol}" in again["results"][0]["detail"]
    assert creates == []
    assert [v["VolumeId"] for v in _restored_from(aws, snap_id)] == [new_vol]


def test_restore_volume_retry_uses_receipt_when_ec2_listing_lags(aws, settings, monkeypatch):  # finding 20
    _, snap_id = _quarantined_backup(aws, settings)
    new_vol = actions.restore_volume(aws, settings, snap_id)["results"][0]["restored_volume_id"]
    real_describe = aws.ec2.describe_volumes
    reads = {"by_id": 0}

    def lagging(**kw):  # the tag filter does not show the new volume yet; describe-by-id catches up on a re-read
        if kw.get("Filters"):
            return {"Volumes": []}
        reads["by_id"] += 1
        if reads["by_id"] == 1:
            raise _client_error("InvalidVolume.NotFound", "DescribeVolumes")
        return real_describe(**kw)

    monkeypatch.setattr(aws.ec2, "describe_volumes", lagging)
    again = actions.restore_volume(aws, settings, snap_id)
    assert statuses(again) == ["skipped"], again
    assert f"already restored as {new_vol}" in again["results"][0]["detail"]
    monkeypatch.setattr(aws.ec2, "describe_volumes", real_describe)
    assert len(_restored_from(aws, snap_id)) == 1


def test_restore_volume_allowed_again_after_restored_volume_deleted(aws, settings):  # finding 20: only live copies block
    _, snap_id = _quarantined_backup(aws, settings)
    first = actions.restore_volume(aws, settings, snap_id)["results"][0]["restored_volume_id"]
    aws.ec2.delete_volume(VolumeId=first)
    again = actions.restore_volume(aws, settings, snap_id)
    assert statuses(again) == ["done"], again
    assert again["results"][0]["restored_volume_id"] != first


def test_existing_backup_of_another_volume_is_never_reused(aws, settings):  # finding 1
    victim = make_volume(aws, {"Name": "victim"})
    vid = victim["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", victim)])
    decoy_vol = make_volume(aws, {"Name": "decoy"})
    decoy = aws.ec2.create_snapshot(
        VolumeId=decoy_vol["VolumeId"],
        TagSpecifications=_tagspec("snapshot", {TAG_BACKUP_OF: vid, TAG_PLAN_ID: pid}),
    )["SnapshotId"]

    receipt = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)

    assert statuses(receipt) == ["done"], receipt
    backup = receipt["results"][0]["backup_snapshot_id"]
    assert backup != decoy
    assert aws.ec2.describe_snapshots(SnapshotIds=[backup])["Snapshots"][0]["VolumeId"] == vid


def test_existing_backup_requires_matching_backup_of_tag(aws, settings, monkeypatch):  # finding 1
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    wrong_tag = {"SnapshotId": "snap-0wrongtag", "VolumeId": vid, "State": "completed",
                 "Tags": [{"Key": TAG_BACKUP_OF, "Value": "vol-0someoneelse"}, {"Key": TAG_PLAN_ID, "Value": "plan-x"}]}
    other_vol = {"SnapshotId": "snap-0othervol", "VolumeId": "vol-0other", "State": "completed",
                 "Tags": [{"Key": TAG_BACKUP_OF, "Value": vid}, {"Key": TAG_PLAN_ID, "Value": "plan-x"}]}
    good = {"SnapshotId": "snap-0good", "VolumeId": vid, "State": "pending",
            "Tags": [{"Key": TAG_BACKUP_OF, "Value": vid}, {"Key": TAG_PLAN_ID, "Value": "plan-x"}]}
    # Even if EC2 ignored the filters, only a snapshot OF this volume, tagged as its backup, is reused.
    monkeypatch.setattr(aws.ec2, "describe_snapshots", lambda **kw: {"Snapshots": [wrong_tag, other_vol]})
    assert actions._existing_backup(aws, vid, "plan-x") is None
    monkeypatch.setattr(aws.ec2, "describe_snapshots", lambda **kw: {"Snapshots": [wrong_tag, other_vol, good]})
    assert actions._existing_backup(aws, vid, "plan-x")["SnapshotId"] == "snap-0good"


def _freeze(settings) -> None:
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    (settings.state_dir / "FREEZE").write_text("", encoding="utf-8")


def test_freeze_mid_batch_stops_remaining_items(aws, settings, monkeypatch):  # finding 2
    vols = [make_volume(aws) for _ in range(3)]
    ids = [v["VolumeId"] for v in vols]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", v) for v in vols])
    real_delete = aws.ec2.delete_volume

    def delete_then_operator_freezes(**kw):
        out = real_delete(**kw)
        _freeze(settings)  # the operator sees the first delete and pulls the switch
        return out

    monkeypatch.setattr(aws.ec2, "delete_volume", delete_then_operator_freezes)
    receipt = actions.quarantine_volumes(aws, settings, pid, ids, signoff=SIG)

    assert statuses(receipt) == ["done", "skipped", "skipped"], receipt
    assert [r["detail"] for r in receipt["results"][1:]] == [actions.FROZEN_DETAIL] * 2
    assert receipt["freeze"] is True
    for vid in ids[1:]:
        assert aws.ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["State"] == "available"
        assert aws.ec2.describe_snapshots(Filters=[{"Name": f"tag:{TAG_BACKUP_OF}", "Values": [vid]}])["Snapshots"] == []


def test_freeze_during_backup_wait_keeps_the_volume(aws, settings, monkeypatch):  # finding 2
    vol = make_volume(aws)
    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])

    class FreezeWhileWaiting:
        def wait(self, **_):
            _freeze(settings)

    monkeypatch.setattr(aws.ec2, "get_waiter", lambda name: FreezeWhileWaiting())
    receipt = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)

    res = receipt["results"][0]
    assert res["status"] == "skipped", receipt
    assert res["detail"].startswith(actions.FROZEN_DETAIL) and res["backup_snapshot_id"]
    assert aws.ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["State"] == "available"


def test_freeze_mid_batch_stops_start_instances(aws, settings, monkeypatch):  # finding 2 (undo tools too)
    insts = [make_instance(aws), make_instance(aws)]
    ids = [i["InstanceId"] for i in insts]
    pid = make_plan(aws, settings, [("instance", "stop_instance", i) for i in insts])
    assert statuses(actions.stop_instances(aws, settings, pid, ids, signoff=SIG)) == ["done", "done"]
    real_start = aws.ec2.start_instances

    def start_then_freeze(**kw):
        out = real_start(**kw)
        _freeze(settings)
        return out

    monkeypatch.setattr(aws.ec2, "start_instances", start_then_freeze)
    receipt = actions.start_instances(aws, settings, ids)
    assert statuses(receipt) == ["done", "skipped"], receipt
    assert receipt["results"][1]["detail"] == actions.FROZEN_DETAIL
    desc = aws.ec2.describe_instances(InstanceIds=[ids[1]])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] == "stopped"


def test_freeze_right_before_stop_after_activity_recheck(aws, settings, monkeypatch):  # finding 2
    inst = make_instance(aws)
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])

    def slow_recheck(clients, s, i):
        _freeze(settings)  # frozen while CloudWatch was being read
        return None

    monkeypatch.setattr(actions, "_became_active", slow_recheck)
    receipt = actions.stop_instances(aws, settings, pid, [iid], signoff=SIG)
    assert statuses(receipt) == ["skipped"]
    assert receipt["results"][0]["detail"] == actions.FROZEN_DETAIL
    desc = aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] == "running"


def _tag_writes(aws, monkeypatch) -> list[tuple[str, list[str], dict[str, str]]]:
    """Spy on every call that writes or deletes tags (explicitly or on create): (call, resources, tags)."""
    seen: list[tuple[str, list[str], dict[str, str]]] = []
    for name in ("create_tags", "delete_tags", "create_snapshot", "create_volume"):
        real = getattr(aws.ec2, name)

        def spy(real=real, name=name, **kw):
            tags = {t["Key"]: t.get("Value", "") for t in kw.get("Tags") or []}
            for spec in kw.get("TagSpecifications") or []:
                tags.update({t["Key"]: t.get("Value", "") for t in spec.get("Tags") or []})
            seen.append((name, list(kw.get("Resources") or []), tags))
            return real(**kw)

        monkeypatch.setattr(aws.ec2, name, spy)
    return seen


def test_undo_tools_mark_human_undo(aws, settings, recycle_bin, monkeypatch):  # finding 7 / 25 (actions side)
    # restore_volume: the NEW volume carries the mark from the moment it exists.
    _, backup = _quarantined_backup(aws, settings)
    restored = actions.restore_volume(aws, settings, backup)["results"][0]
    assert restored["status"] == "done", restored
    new_tags = tags_to_dict(aws.ec2.describe_volumes(VolumeIds=[restored["restored_volume_id"]])["Volumes"][0]["Tags"])
    assert actions._parse_utc(new_tags.get(TAG_HUMAN_UNDO_AT)) is not None, new_tags

    # start_instances: the instance.
    inst = make_instance(aws)
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])
    assert statuses(actions.stop_instances(aws, settings, pid, [iid], signoff=SIG)) == ["done"]
    assert statuses(actions.start_instances(aws, settings, [iid])) == ["done"]
    desc = aws.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert actions._parse_utc(tags_to_dict(desc["Tags"]).get(TAG_HUMAN_UNDO_AT)) is not None

    # cancel_address_quarantine: the address.
    addr = make_address(aws)
    aid = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    assert statuses(actions.quarantine_addresses(aws, settings, pid, [aid], signoff=SIG)) == ["done"]
    assert statuses(actions.cancel_address_quarantine(aws, settings, aid)) == ["done"]
    assert actions._parse_utc(_addr_tags(aws, aid).get(TAG_HUMAN_UNDO_AT)) is not None

    # restore_snapshot: the snapshot (moto really deleted it, so record the tag call Warden makes).
    snap = make_snapshot(aws)
    sid = snap["SnapshotId"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    assert statuses(actions.recycle_snapshots(aws, settings, pid, [sid], signoff=SIG)) == ["done"]
    tagged: list[dict] = []
    monkeypatch.setattr(aws.ec2, "create_tags", lambda **kw: tagged.append(kw) or {})
    receipt = actions.restore_snapshot(aws, settings, sid)
    assert statuses(receipt) == ["done"], receipt
    marks = [t["Value"] for kw in tagged if kw["Resources"] == [sid] for t in kw["Tags"] if t["Key"] == TAG_HUMAN_UNDO_AT]
    assert len(marks) == 1 and actions._parse_utc(marks[0]) is not None


def test_human_undo_mark_failure_never_fails_the_undo(aws, settings, monkeypatch):  # finding 7 / 25
    addr = make_address(aws)
    aid = addr["AllocationId"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    assert statuses(actions.quarantine_addresses(aws, settings, pid, [aid], signoff=SIG)) == ["done"]

    def denied(**kw):
        raise _client_error("UnauthorizedOperation", "CreateTags")

    monkeypatch.setattr(aws.ec2, "create_tags", denied)
    receipt = actions.cancel_address_quarantine(aws, settings, aid)
    res = receipt["results"][0]
    assert res["status"] == "done", receipt
    assert "WARNING" in res["detail"] and TAG_HUMAN_UNDO_AT in res["detail"]
    assert TAG_QUARANTINED_UNTIL not in _addr_tags(aws, aid)  # the undo itself happened


def test_warden_never_writes_or_deletes_the_protect_tag(aws, settings, recycle_bin, monkeypatch):  # finding 14
    # warden:protect=false is not a protection, so these may be acted on; the key must never be written or deleted.
    unprotected = {"warden:protect": "false"}
    vol = make_volume(aws, {"Name": "scratch", "warden:protect": "false", "Warden:Protect": "no"})
    inst = make_instance(aws, unprotected)
    addr = make_address(aws, unprotected)
    snap = make_snapshot(aws, unprotected)
    # An older backup that still carries the key must not plant it on the restored volume either.
    _, old_backup = _quarantined_backup(aws, settings)
    aws.ec2.create_tags(Resources=[old_backup], Tags=[{"Key": "WARDEN:PROTECT", "Value": "false"}])
    writes = _tag_writes(aws, monkeypatch)  # from here on, only Warden writes tags

    vid = vol["VolumeId"]
    pid = make_plan(aws, settings, [("volume", "quarantine_volume", vol)])
    res = actions.quarantine_volumes(aws, settings, pid, [vid], signoff=SIG)["results"][0]
    assert res["status"] == "done", res
    backup_tags = tags_to_dict(aws.ec2.describe_snapshots(SnapshotIds=[res["backup_snapshot_id"]])["Snapshots"][0]["Tags"])
    assert backup_tags["Name"] == "scratch"
    assert statuses(actions.restore_volume(aws, settings, res["backup_snapshot_id"])) == ["done"]
    assert statuses(actions.restore_volume(aws, settings, old_backup)) == ["done"]

    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])
    assert statuses(actions.stop_instances(aws, settings, pid, [inst["InstanceId"]], signoff=SIG)) == ["done"]
    assert statuses(actions.start_instances(aws, settings, [inst["InstanceId"]])) == ["done"]
    pid = make_plan(aws, settings, [("address", "quarantine_address", addr)])
    assert statuses(actions.quarantine_addresses(aws, settings, pid, [addr["AllocationId"]], signoff=SIG)) == ["done"]
    assert statuses(actions.cancel_address_quarantine(aws, settings, addr["AllocationId"])) == ["done"]
    pid = make_plan(aws, settings, [("snapshot", "recycle_snapshot", snap)])
    assert statuses(actions.recycle_snapshots(aws, settings, pid, [snap["SnapshotId"]], signoff=SIG)) == ["done"]

    offending = [(name, key) for name, _, tags in writes for key in tags if key.strip().lower() == "warden:protect"]
    assert offending == []
    assert {"create_snapshot", "create_volume", "create_tags", "delete_tags"} <= {name for name, _, _ in writes}


def test_ledger_failure_after_mutation_keeps_the_receipt(aws, settings, monkeypatch):  # finding 4
    inst = make_instance(aws)
    iid = inst["InstanceId"]
    pid = make_plan(aws, settings, [("instance", "stop_instance", inst)])

    def ledger_locked(*a, **k):
        raise PermissionError("audit.jsonl is locked by OneDrive")

    monkeypatch.setattr(audit, "audit", ledger_locked)
    receipt = actions.stop_instances(aws, settings, pid, [iid], signoff=SIG)

    assert statuses(receipt) == ["done"], receipt
    assert "audit.jsonl is locked" in receipt["ledger_error"]
    saved = audit.load_receipt(settings, receipt["receipt_id"])
    assert saved is not None and saved["results"][0]["status"] == "done" and saved.get("ledger_error")
    started = actions.start_instances(aws, settings, [iid])  # the undo still finds the stop receipt
    assert statuses(started) == ["done"], started
