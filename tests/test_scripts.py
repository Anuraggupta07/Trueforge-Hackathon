"""Demo scripts (preflight, plant, reset) against moto. Recycle Bin is stubbed (moto lacks rbin)."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from warden.policy import tags_to_dict

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

plant = importlib.import_module("plant")
reset = importlib.import_module("reset")
preflight = importlib.import_module("preflight")


class FakeRbin:
    """Minimal in-memory Recycle Bin client."""

    def __init__(self, denied: bool = False) -> None:
        self.rules: dict[str, dict] = {}
        self.denied = denied

    def _check(self, op: str) -> None:
        if self.denied:
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, op)

    def list_rules(self, ResourceType: str, **_: object) -> dict:
        self._check("ListRules")
        return {"Rules": [{"Identifier": k, "RuleArn": f"arn:rbin:{k}",
                           "Description": r["Description"]} for k, r in self.rules.items()]}

    def get_rule(self, Identifier: str) -> dict:
        self._check("GetRule")
        return {"Identifier": Identifier, **self.rules[Identifier]}

    def create_rule(self, **kwargs: object) -> dict:
        self._check("CreateRule")
        ident = f"rule{len(self.rules) + 1}"
        self.rules[ident] = {**kwargs, "Status": "available"}
        return {"Identifier": ident}

    def list_tags_for_resource(self, ResourceArn: str) -> dict:
        return {"Tags": self.rules[ResourceArn.rsplit(":", 1)[1]].get("Tags", [])}

    def delete_rule(self, Identifier: str) -> dict:
        self.rules.pop(Identifier)
        return {}


@pytest.fixture(autouse=True)
def lt_volume_tags(aws):
    """moto ignores a launch template's 'volume' TagSpecifications; apply them like AWS does."""
    ec2 = aws.ec2
    original = ec2.run_instances

    def run_instances(**kwargs):
        resp = original(**kwargs)
        lt_ref = kwargs.get("LaunchTemplate")
        if lt_ref:
            data = ec2.describe_launch_template_versions(
                LaunchTemplateId=lt_ref["LaunchTemplateId"], Versions=[lt_ref.get("Version", "$Default")]
            )["LaunchTemplateVersions"][0]["LaunchTemplateData"]
            tags = [t for spec in data.get("TagSpecifications", []) if spec["ResourceType"] == "volume"
                    for t in spec["Tags"]]
            vol_ids = [m["Ebs"]["VolumeId"] for i in resp["Instances"]
                       for m in ec2.describe_instances(InstanceIds=[i["InstanceId"]])["Reservations"][0]
                       ["Instances"][0].get("BlockDeviceMappings", [])]
            if tags and vol_ids:
                ec2.create_tags(Resources=vol_ids, Tags=tags)
        return resp

    ec2.run_instances = run_instances


@pytest.fixture
def rbin(aws):
    fake = FakeRbin()
    aws.__dict__["rbin"] = fake  # overrides the cached_property
    return fake


def _names(items: list[dict]) -> set[str]:
    return {i.get("name", "") for i in items}


def _plant(aws, settings) -> tuple[list[str], float]:
    lines: list[str] = []
    waste = plant.Planter(aws, settings, out=lines.append, waiter_delay=0).run()
    return lines, waste


def test_plant_creates_demo_resources(aws, settings, rbin):
    lines, waste = _plant(aws, settings)
    assert not [line for line in lines if "FAILED" in line], lines
    found = reset.find_demo_resources(aws, include_recycle_rule=True)
    vol_names = _names(found["volumes"])
    assert {plant.OLD_DATA, plant.PROD_DISK, plant.TF_DISK, plant.INJECTION_NAME, plant.LEAK_VOLUME} <= vol_names
    assert {plant.ORPHAN_SNAPSHOT, plant.GOLDEN_SNAPSHOT} <= _names(found["snapshots"])
    assert {plant.LEAK_LT, plant.WEB_LT} <= _names(found["launch_templates"])
    assert _names(found["images"]) == {plant.GOLDEN_AMI}
    assert _names(found["addresses"]) == {plant.UNUSED_IP}
    assert _names(found["instances"]) == {plant.IDLE_SERVER}
    assert len(found["recycle_rules"]) == 1
    # every volume is in one AZ, and helper volumes are gone
    vols = aws.ec2.describe_volumes()["Volumes"]
    assert len({v["AvailabilityZone"] for v in vols if tags_to_dict(v.get("Tags")).get("warden:demo")}) == 1
    assert not any(n.endswith("-helper") for n in vol_names)
    # injection volume carries the hostile tags verbatim (as data)
    inj = [v for v in vols if tags_to_dict(v.get("Tags")).get("Name") == plant.INJECTION_NAME][0]
    assert tags_to_dict(inj["Tags"])["note"] == plant.INJECTION_NOTE
    assert waste > 0 and any("Estimated monthly waste" in line for line in lines)


def test_plant_is_idempotent(aws, settings, rbin):
    _plant(aws, settings)
    before = reset.find_demo_resources(aws, include_recycle_rule=True)
    lines, _ = _plant(aws, settings)
    after = reset.find_demo_resources(aws, include_recycle_rule=True)
    assert {k: sorted(i["id"] for i in v) for k, v in before.items()} == \
           {k: sorted(i["id"] for i in v) for k, v in after.items()}
    assert not [line for line in lines if "[created" in line], lines


def test_plant_reports_recycle_bin_denied(aws, settings):
    aws.__dict__["rbin"] = FakeRbin(denied=True)
    lines, _ = _plant(aws, settings)
    assert any("BLOCKED" in line and "permanent" in line for line in lines)


def test_reset_dry_run_deletes_nothing(aws, settings, rbin):
    _plant(aws, settings)
    before = reset.find_demo_resources(aws, include_recycle_rule=True)
    lines: list[str] = []
    reset.reset(aws, settings, yes=False, include_recycle_rule=True, out=lines.append, waiter_delay=0)
    assert any("Would delete" in line for line in lines)
    assert reset.find_demo_resources(aws, include_recycle_rule=True) == before


def test_reset_removes_only_demo_resources(aws, settings, rbin):
    ec2 = aws.ec2
    keep_vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=5, VolumeType="gp3",
                                 TagSpecifications=[{"ResourceType": "volume",
                                                     "Tags": [{"Key": "Name", "Value": "not-demo"},
                                                              {"Key": "warden:demo", "Value": "false"}]}])
    keep_ip = ec2.allocate_address(Domain="vpc")
    _plant(aws, settings)
    lines: list[str] = []
    reset.reset(aws, settings, yes=True, include_recycle_rule=True, out=lines.append, waiter_delay=0)
    assert not [line for line in lines if "FAILED" in line], lines
    left = reset.find_demo_resources(aws, include_recycle_rule=True)
    assert all(not items for items in left.values()), left
    assert rbin.rules == {}
    assert ec2.describe_volumes(VolumeIds=[keep_vol["VolumeId"]])["Volumes"]
    assert ec2.describe_addresses(AllocationIds=[keep_ip["AllocationId"]])["Addresses"]
    assert any("expire on their own" in line for line in lines)


def test_reset_keeps_recycle_rule_by_default(aws, settings, rbin):
    _plant(aws, settings)
    reset.reset(aws, settings, yes=True, out=lambda _: None, waiter_delay=0)
    assert len(rbin.rules) == 1


def test_preflight_is_read_only(aws, settings, rbin):
    before = aws.ec2.describe_volumes()["Volumes"], aws.ec2.describe_instances()["Reservations"]
    rows = preflight.run_checks(aws, settings)
    text = preflight.render(rows)
    checks = {r["check"]: r for r in rows}
    assert checks["STS identity"]["status"] == "OK"
    assert "123456789012" in checks["STS identity"]["detail"]
    assert checks["Default VPC + subnet"]["status"] == "OK"
    assert checks["Recycle Bin"]["status"] == "WARN"  # rule missing until plant.py
    assert "CHECK" in text
    after = aws.ec2.describe_volumes()["Volumes"], aws.ec2.describe_instances()["Reservations"]
    assert before == after


def test_preflight_reports_blocked_items(aws, settings):
    aws.__dict__["rbin"] = FakeRbin(denied=True)
    rows = preflight.run_checks(aws, settings)
    rb = {r["check"]: r for r in rows}["Recycle Bin"]
    assert rb["status"] == "BLOCKED" and "recycle_snapshot" in rb["disables"]
    assert "What the non-OK items disable" in preflight.render(rows)
