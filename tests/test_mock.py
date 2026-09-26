"""Mock mode: Warden against a local moto server, with the Recycle Bin / instance-age / CloudTrail shims."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError
from moto.server import ThreadedMotoServer

from warden import mock, scanner
from warden.aws import AwsClients, dry_run
from warden.config import TAG_RECYCLE, TAG_RECYCLE_VALUE, load_settings

REGION = "us-east-1"
RULE_TAGS = [{"ResourceTagKey": TAG_RECYCLE, "ResourceTagValue": TAG_RECYCLE_VALUE}]


@pytest.fixture(scope="module")
def endpoint():
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    yield f"http://{host}:{port}"
    server.stop()


@pytest.fixture
def msettings(endpoint, tmp_path):
    return load_settings(env={"AWS_REGION": REGION, "WARDEN_STATE_DIR": str(tmp_path / "state"),
                              "WARDEN_MOCK_ENDPOINT": endpoint})


@pytest.fixture
def maws(msettings):
    return AwsClients(msettings)


def _snapshot(ec2, **tags: str) -> str:
    vol = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    tag_list = [{"Key": k, "Value": v} for k, v in tags.items()]
    spec = [{"ResourceType": "snapshot", "Tags": tag_list}] if tag_list else []
    return ec2.create_snapshot(VolumeId=vol, TagSpecifications=spec)["SnapshotId"]


def _visible(ec2, snap_id: str) -> bool:
    return any(s["SnapshotId"] == snap_id for s in ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"])


def _rule(maws, **extra) -> str:
    return maws.rbin.create_rule(
        ResourceType="EBS_SNAPSHOT", ResourceTags=RULE_TAGS,
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"}, **extra,
    )["Identifier"]


def test_settings_mock_endpoint():
    assert load_settings(env={"AWS_REGION": REGION}).mock is False
    s = load_settings(env={"AWS_REGION": REGION, "WARDEN_MOCK_ENDPOINT": "http://127.0.0.1:5000/"})
    assert s.mock and s.mock_endpoint == "http://127.0.0.1:5000"
    with pytest.raises(ValueError, match="WARDEN_MOCK_ENDPOINT"):
        load_settings(env={"AWS_REGION": REGION, "WARDEN_MOCK_ENDPOINT": "127.0.0.1:5000"})


def test_mock_mode_ignores_real_credentials(monkeypatch, msettings, endpoint):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAREALKEYSHOULDNOTBEUSED")
    clients = AwsClients(msettings)
    assert clients.session.get_credentials().access_key == "testing"
    assert clients.ec2.meta.endpoint_url == endpoint
    assert clients.account_id() == mock.MOCK_ACCOUNT_ID


def test_rbin_rule_crud_and_scanner_readiness(maws):
    assert scanner.recycle_bin_ready(maws) is False
    rule_id = _rule(maws, Description="keep", Tags=[{"Key": "warden:demo", "Value": "true"}])
    listed = maws.rbin.list_rules(ResourceType="EBS_SNAPSHOT")["Rules"]
    assert [r["Identifier"] for r in listed] == [rule_id]
    assert maws.rbin.get_rule(Identifier=rule_id)["Status"] == "available"
    assert maws.rbin.list_tags_for_resource(ResourceArn=listed[0]["RuleArn"])["Tags"] == [
        {"Key": "warden:demo", "Value": "true"}]
    assert scanner.recycle_bin_ready(maws) is True
    maws.rbin.delete_rule(Identifier=rule_id)
    with pytest.raises(ClientError, match="ResourceNotFoundException"):
        maws.rbin.get_rule(Identifier=rule_id)


def test_rule_state_is_shared_between_processes(maws, msettings):
    _rule(maws)
    assert scanner.recycle_bin_ready(AwsClients(msettings)) is True  # fresh clients read the state file


def test_covered_delete_goes_to_bin_and_restores_with_same_id(maws):
    _rule(maws)
    ec2 = maws.ec2
    snap = _snapshot(ec2, **{TAG_RECYCLE: TAG_RECYCLE_VALUE})
    assert dry_run(ec2.delete_snapshot, SnapshotId=snap) == "would_succeed"
    assert _visible(ec2, snap)  # the dry run changed nothing
    ec2.delete_snapshot(SnapshotId=snap)
    assert not _visible(ec2, snap)
    binned = ec2.list_snapshots_in_recycle_bin(SnapshotIds=[snap])["Snapshots"]
    assert [s["SnapshotId"] for s in binned] == [snap]
    exit_in = binned[0]["RecycleBinExitTime"] - datetime.now(timezone.utc)
    assert timedelta(days=6, hours=23) < exit_in <= timedelta(days=7)
    ec2.restore_snapshot_from_recycle_bin(SnapshotId=snap)
    assert _visible(ec2, snap)
    assert ec2.list_snapshots_in_recycle_bin()["Snapshots"] == []
    with pytest.raises(ClientError, match="InvalidSnapshot.NotFound"):
        ec2.restore_snapshot_from_recycle_bin(SnapshotId=snap)


def test_uncovered_delete_is_permanent(maws):
    _rule(maws)
    ec2 = maws.ec2
    snap = _snapshot(ec2, team="x")  # rule needs warden:recycle=true on the snapshot itself
    ec2.delete_snapshot(SnapshotId=snap)
    assert not _visible(ec2, snap)
    assert ec2.list_snapshots_in_recycle_bin()["Snapshots"] == []


def test_expired_bin_entries_are_purged(maws, msettings):
    _rule(maws)
    ec2 = maws.ec2
    snap = _snapshot(ec2, **{TAG_RECYCLE: TAG_RECYCLE_VALUE})
    ec2.delete_snapshot(SnapshotId=snap)
    data = mock._load(msettings)
    data["bin"][snap]["RecycleBinExitTime"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    mock._save(msettings, data)
    assert ec2.list_snapshots_in_recycle_bin()["Snapshots"] == []
    with pytest.raises(ClientError):
        ec2.describe_snapshots(SnapshotIds=[snap])  # gone from moto for real


def test_instances_look_launched_earlier(maws):
    ec2 = maws.ec2
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    iid = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    age = datetime.now(timezone.utc) - inst["LaunchTime"]
    assert age >= mock.MOCK_INSTANCE_AGE - timedelta(minutes=1)


def test_seeded_metrics_make_the_instance_idle(maws, msettings):
    ec2 = maws.ec2
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    iid = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    mock.seed_idle_metrics(maws.cloudwatch, iid)
    inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    activity = scanner._activity(maws, iid, msettings, datetime.now(timezone.utc), launched=inst["LaunchTime"],
                                 lookback_minutes=30)
    assert activity["datapoints"] > 0
    assert activity["max_cpu_pct"] < msettings.idle_cpu_pct


def test_cloudtrail_lookup_returns_no_events(maws):
    assert maws.cloudtrail.lookup_events(MaxResults=1)["Events"] == []


def test_evidence_clients_fail_fast_but_ec2_keeps_robust_retries():  # LEAD-1
    from warden.aws import AwsClients

    clients = AwsClients(load_settings(env={"AWS_REGION": "us-east-1"}))
    for name in ("cloudtrail", "rbin", "route53", "elbv2"):
        cfg = getattr(clients, name).meta.config
        assert cfg.retries["total_max_attempts"] <= 2 and cfg.read_timeout <= 8 and cfg.connect_timeout <= 3, name
    assert clients.ec2.meta.config.retries["total_max_attempts"] == 9


def test_scan_budget_setting():  # LEAD-1
    assert load_settings(env={"AWS_REGION": "us-east-1"}).scan_budget_seconds == 90
    assert load_settings(env={"AWS_REGION": "us-east-1", "WARDEN_SCAN_BUDGET_SECONDS": "30"}).scan_budget_seconds == 30
