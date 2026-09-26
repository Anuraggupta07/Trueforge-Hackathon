import copy
import json

import pytest

from warden import audit, plan
from warden.aws import AwsClients, dry_run, error_code
from warden.config import load_settings
from warden.plan import PlanItem

ACCOUNT = "123456789012"
REGION = "us-east-1"

VOLUME = {
    "VolumeId": "vol-1",
    "State": "available",
    "Size": 8,
    "VolumeType": "gp2",
    "Attachments": [],
    "Tags": [{"Key": "b", "Value": "2"}, {"Key": "a", "Value": "1"}],
    "CreateTime": "ignored",
}


def test_fingerprint_stable_and_order_insensitive():
    fp = plan.fingerprint("volume", VOLUME)
    reordered = copy.deepcopy(VOLUME)
    reordered["Tags"].reverse()
    reordered["CreateTime"] = "different but irrelevant"
    assert plan.fingerprint("volume", reordered) == fp
    assert len(fp) == 64


def _set(key, value):
    return lambda v: v.__setitem__(key, value)


@pytest.mark.parametrize(
    "change",
    [
        _set("State", "in-use"),
        _set("Attachments", [{"InstanceId": "i-1"}]),
        _set("Size", 9),
        _set("VolumeType", "gp3"),
        lambda v: v["Tags"].append({"Key": "env", "Value": "production"}),
    ],
)
def test_fingerprint_detects_change(change):
    changed = copy.deepcopy(VOLUME)
    change(changed)
    assert plan.fingerprint("volume", changed) != plan.fingerprint("volume", VOLUME)


def test_fingerprint_other_types():
    snap = {"State": "completed", "VolumeId": "vol-1", "Tags": []}
    assert plan.fingerprint("snapshot", snap) != plan.fingerprint("snapshot", {**snap, "VolumeId": "vol-2"})
    inst = {"State": {"Name": "running"}, "InstanceType": "t3.micro"}
    stopped = {**inst, "State": {"Name": "stopped"}}
    assert plan.fingerprint("instance", inst) != plan.fingerprint("instance", stopped)
    addr = {"PublicIp": "1.2.3.4"}
    assert plan.fingerprint("address", addr) != plan.fingerprint("address", {**addr, "AssociationId": "eipassoc-1"})
    assert plan.fingerprint("address", addr) == plan.fingerprint("address", dict(addr))


def _items() -> list[PlanItem]:
    return [
        PlanItem("vol-1", "volume", "act", "quarantine_volume", "f1"),
        PlanItem("vol-2", "volume", "act", "quarantine_volume", "f2"),
        PlanItem("vol-keep", "volume", "keep", None, "f3"),
        PlanItem("vol-review", "volume", "review", None, "f4"),
        PlanItem("snap-1", "snapshot", "act", "recycle_snapshot", "f5"),
        PlanItem("snap-2", "snapshot", "act", "delete_snapshot", "f6"),
        PlanItem("eipalloc-1", "address", "act", "release_address", "f7"),
        PlanItem("i-1", "instance", "act", "stop_instance", "f8"),
    ] + [PlanItem(f"vol-b{i}", "volume", "act", "quarantine_volume", f"b{i}") for i in range(6)]


@pytest.fixture
def saved(settings):
    p = plan.new_plan(ACCOUNT, REGION, _items(), settings, now=1000.0)
    plan.save_plan(p, settings)
    return p


def validate(settings, p, action, ids, **kw):
    kw.setdefault("now", 1001.0)
    kw.setdefault("account_id", ACCOUNT)
    kw.setdefault("region", REGION)
    return plan.validate_request(p.plan_id, action, ids, settings, **kw)


def test_new_plan_and_roundtrip(settings, saved):
    assert saved.plan_id.startswith("plan-")
    assert saved.expires_at == 1000.0 + settings.plan_ttl_minutes * 60
    path = settings.state_dir / "plans" / f"{saved.plan_id}.json"
    assert path.exists()
    assert plan.load_plan(saved.plan_id, settings) == saved
    assert plan.Plan.from_dict(json.loads(path.read_text())) == saved


def test_actions_table():
    assert {k: (v.resource_type, v.reversible) for k, v in plan.ACTIONS.items()} == {
        "quarantine_volume": ("volume", True),
        "recycle_snapshot": ("snapshot", True),
        "delete_snapshot": ("snapshot", False),
        "stop_instance": ("instance", True),
        "quarantine_address": ("address", True),
        "release_address": ("address", False),
    }


def test_happy_path_dedupes(settings, saved):
    p, ok, rej = validate(settings, saved, "quarantine_volume", ["vol-1", "vol-2", "vol-1"])
    assert p.plan_id == saved.plan_id and ok == ["vol-1", "vol-2"] and rej == {}


def test_irreversible_single(settings, saved):
    assert validate(settings, saved, "release_address", ["eipalloc-1"])[1] == ["eipalloc-1"]
    assert validate(settings, saved, "delete_snapshot", ["snap-2"])[1] == ["snap-2"]


@pytest.mark.parametrize(
    "action,ids,kw,needle",
    [
        ("nuke", ["vol-1"], {}, "unknown action"),
        ("quarantine_volume", ["vol-1"], {"now": 1000.0 + 3600}, "expired"),
        ("quarantine_volume", ["vol-1"], {"account_id": "999999999999"}, "account"),
        ("quarantine_volume", ["vol-1"], {"region": "eu-west-1"}, "eu-west-1"),
        ("quarantine_volume", [], {}, "non-empty"),
        ("quarantine_volume", "vol-1", {}, "non-empty list"),
        ("quarantine_volume", ["vol-1", ""], {}, "non-empty string"),
        ("quarantine_volume", ["*"], {}, "wildcard"),
        ("quarantine_volume", ["ALL"], {}, "wildcard"),
        ("quarantine_volume", ["vol-*"], {}, "wildcard"),
        ("quarantine_volume", ["vol-1", "vol-2"] + [f"vol-b{i}" for i in range(4)], {}, "exceeds"),
        ("release_address", ["eipalloc-1", "eipalloc-2"], {}, "exactly one"),
        ("delete_snapshot", ["snap-1", "snap-2"], {}, "exactly one"),
    ],
)
def test_request_level_rejections(settings, saved, action, ids, kw, needle):
    _, ok, rej = validate(settings, saved, action, ids, **kw)
    assert ok == []
    assert list(rej) == ["*"]
    assert needle in rej["*"]


@pytest.mark.parametrize("bad", ["plan-doesnotexist", "../../etc/passwd", "plan-../x", "plan-a/b", "", None])
def test_missing_and_traversal_plan_ids(settings, saved, bad):
    p, ok, rej = plan.validate_request(bad, "quarantine_volume", ["vol-1"], settings, ACCOUNT, REGION)
    assert p is None and ok == [] and "not found" in rej["*"]
    assert plan.load_plan(bad, settings) is None


def test_per_id_rejections(settings, saved):
    ids = ["vol-1", "vol-missing", "vol-keep", "vol-review", "snap-1"]
    _, ok, rej = validate(settings, saved, "quarantine_volume", ids)
    assert ok == ["vol-1"]
    assert "not in plan" in rej["vol-missing"]
    assert "'keep'" in rej["vol-keep"]
    assert "'review'" in rej["vol-review"]
    assert "snapshot" in rej["snap-1"]
    # right type, wrong action
    _, ok, rej = validate(settings, saved, "delete_snapshot", ["snap-1"])
    assert ok == [] and "recycle_snapshot" in rej["snap-1"]
    _, ok, rej = validate(settings, saved, "recycle_snapshot", ["snap-1", "snap-2"])
    assert ok == ["snap-1"] and "delete_snapshot" in rej["snap-2"]


def test_custom_max_batch(tmp_path):
    s = load_settings(env={"WARDEN_STATE_DIR": str(tmp_path), "WARDEN_MAX_BATCH": "2"})
    p = plan.new_plan(ACCOUNT, REGION, _items(), s, now=0.0)
    plan.save_plan(p, s)
    ids = ["vol-1", "vol-2", "vol-b0"]
    _, ok, rej = plan.validate_request(p.plan_id, "quarantine_volume", ids, s, ACCOUNT, REGION, now=1.0)
    assert ok == [] and "exceeds" in rej["*"]


def test_audit_and_receipts(settings):
    rid = audit.new_id("rcpt")
    assert rid.startswith("rcpt-")
    with pytest.raises(ValueError):
        audit.new_id("evil")
    audit.audit(settings, "scan", plan_id="plan-x", obj=object())
    line = json.loads((settings.state_dir / "audit.jsonl").read_text().splitlines()[0])
    assert line["event"] == "scan" and line["ts"].endswith("Z") and line["plan_id"] == "plan-x"
    r1 = {
        "receipt_id": rid,
        "action": "stop_instance",
        "plan_id": "p",
        "finished_at": "2026-09-26T10:00:00Z",
        "counts": {"done": 1, "skipped": 0, "failed": 0},
    }
    r2 = {**r1, "receipt_id": audit.new_id("rcpt"), "finished_at": "2026-09-26T11:00:00Z"}
    audit.save_receipt(settings, r1)
    audit.save_receipt(settings, r2)
    assert audit.load_receipt(settings, rid) == r1
    assert audit.load_receipt(settings, "../x") is None
    assert [r["receipt_id"] for r in audit.list_receipts(settings)] == [r2["receipt_id"], rid]
    assert len(audit.list_receipts(settings, limit=1)) == 1


def test_aws_helpers(aws: AwsClients):
    assert aws.account_id() == "123456789012"
    assert aws.ec2 is aws.ec2
    vol = aws.ec2.create_volume(AvailabilityZone="us-east-1a", Size=1)
    assert dry_run(aws.ec2.delete_volume, VolumeId=vol["VolumeId"]) in ("would_succeed", "error: DryRunNotHonoured")
    assert dry_run(aws.ec2.delete_volume, VolumeId=123).startswith("error: ")
    assert error_code(ValueError("x")) == "ValueError"
