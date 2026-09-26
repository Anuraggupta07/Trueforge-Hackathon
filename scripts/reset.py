"""Delete every Warden demo resource (tagged warden:demo=true) - and nothing else.

Run: uv run python scripts/reset.py            # prints what it WOULD delete
     uv run python scripts/reset.py --yes      # actually deletes
     uv run python scripts/reset.py --yes --include-recycle-rule
"""

from __future__ import annotations

import argparse
from typing import Any, Callable

import _common  # noqa: F401  (sets up sys.path if needed)
from _common import DEMO_FILTER, AwsClients, is_demo, list_snapshot_rules, run_main
from warden.aws import error_code
from warden.config import DEMO_TAG, Settings, load_settings
from warden.policy import tags_to_dict

LIVE_INSTANCE_STATES = ["pending", "running", "stopping", "stopped"]


def _name(tag_list: list[dict] | None) -> str:
    return tags_to_dict(tag_list).get("Name", "")


def find_demo_resources(clients: AwsClients, include_recycle_rule: bool = False) -> dict[str, list[dict]]:
    """Everything tagged warden:demo=true, grouped by type (double-checked client-side)."""
    ec2 = clients.ec2
    found: dict[str, list[dict]] = {}

    instances = []
    for page in ec2.get_paginator("describe_instances").paginate(Filters=DEMO_FILTER + [
            {"Name": "instance-state-name", "Values": LIVE_INSTANCE_STATES}]):
        instances += [i for r in page["Reservations"] for i in r["Instances"]]
    found["instances"] = [
        {"id": i["InstanceId"], "name": _name(i.get("Tags")), "state": i["State"]["Name"]}
        for i in instances if is_demo(i.get("Tags"))
    ]
    found["launch_templates"] = [
        {"id": lt["LaunchTemplateId"], "name": lt.get("LaunchTemplateName", "")}
        for lt in ec2.describe_launch_templates(Filters=DEMO_FILTER)["LaunchTemplates"]
        if is_demo(lt.get("Tags"))
    ]
    found["images"] = [
        {"id": img["ImageId"], "name": img.get("Name", "")}
        for img in ec2.describe_images(Owners=["self"], Filters=DEMO_FILTER)["Images"]
        if is_demo(img.get("Tags"))
    ]
    volumes = []
    for page in ec2.get_paginator("describe_volumes").paginate(Filters=DEMO_FILTER):
        volumes += page["Volumes"]
    found["volumes"] = [
        {"id": v["VolumeId"], "name": _name(v.get("Tags")), "state": v["State"]}
        for v in volumes if is_demo(v.get("Tags")) and v["State"] not in ("deleting", "deleted")
    ]
    snapshots = []
    for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"], Filters=DEMO_FILTER):
        snapshots += page["Snapshots"]
    found["snapshots"] = [
        {"id": s["SnapshotId"], "name": _name(s.get("Tags")), "state": s.get("State", "")}
        for s in snapshots if is_demo(s.get("Tags"))
    ]
    found["addresses"] = [
        {"id": a["AllocationId"], "name": _name(a.get("Tags")), "public_ip": a.get("PublicIp", ""),
         "association_id": a.get("AssociationId")}
        for a in ec2.describe_addresses(Filters=DEMO_FILTER)["Addresses"]
        if is_demo(a.get("Tags")) and a.get("AllocationId")
    ]
    found["recycle_rules"] = _demo_rules(clients) if include_recycle_rule else []
    return found


def _demo_rules(clients: AwsClients) -> list[dict]:
    """Recycle Bin rules that carry the warden:demo=true resource tag."""
    rules = []
    try:
        for rule in list_snapshot_rules(clients):
            arn = rule.get("RuleArn")
            tags = clients.rbin.list_tags_for_resource(ResourceArn=arn).get("Tags", []) if arn else []
            if is_demo(tags):
                rules.append({"id": rule["Identifier"], "name": rule.get("Description", "")})
    except Exception as err:
        print(f"  (could not list Recycle Bin rules: {error_code(err)})")
    return rules


class Resetter:
    """Deletes the resources returned by find_demo_resources, in a safe order."""

    def __init__(self, clients: AwsClients, out: Callable[[str], None] = print, waiter_delay: int = 5) -> None:
        self.clients = clients
        self.ec2 = clients.ec2
        self.out = out
        self.delay = waiter_delay

    def _do(self, label: str, fn: Callable[[], Any]) -> bool:
        try:
            fn()
            self.out(f"  deleted   {label}")
            return True
        except Exception as err:
            self.out(f"  FAILED    {label}: {error_code(err)}: {str(err)[:160]}")
            return False

    def run(self, found: dict[str, list[dict]]) -> None:
        ids = [i["id"] for i in found["instances"]]
        if ids:
            self._do(f"instances {', '.join(ids)} (terminate)",
                     lambda: self.ec2.terminate_instances(InstanceIds=ids))
            self.out("  waiting for instances to terminate...")
            try:
                self.ec2.get_waiter("instance_terminated").wait(
                    InstanceIds=ids, WaiterConfig={"Delay": self.delay, "MaxAttempts": 120})
            except Exception as err:
                self.out(f"  (wait failed: {error_code(err)}; in-use volumes may be skipped)")
        for lt in found["launch_templates"]:
            self._do(f"launch template {lt['id']} {lt['name']}",
                     lambda lt=lt: self.ec2.delete_launch_template(LaunchTemplateId=lt["id"]))
        for img in found["images"]:
            self._do(f"AMI {img['id']} {img['name']} (deregister)",
                     lambda img=img: self.ec2.deregister_image(ImageId=img["id"]))
        for vol in self._refresh_volumes(found["volumes"]):
            if vol["state"] == "in-use":
                self.out(f"  skipped   volume {vol['id']} {vol['name']}: still in use (attached)")
                continue
            self._do(f"volume {vol['id']} {vol['name']}",
                     lambda vol=vol: self.ec2.delete_volume(VolumeId=vol["id"]))
        for snap in found["snapshots"]:
            self._do(f"snapshot {snap['id']} {snap['name']}",
                     lambda snap=snap: self.ec2.delete_snapshot(SnapshotId=snap["id"]))
        for addr in found["addresses"]:
            if addr["association_id"]:
                self.out(f"  skipped   Elastic IP {addr['public_ip']}: associated ({addr['association_id']})")
                continue
            self._do(f"Elastic IP {addr['public_ip']} ({addr['id']}) (release)",
                     lambda addr=addr: self.ec2.release_address(AllocationId=addr["id"]))
        for rule in found["recycle_rules"]:
            self._do(f"Recycle Bin rule {rule['id']}",
                     lambda rule=rule: self.clients.rbin.delete_rule(Identifier=rule["id"]))

    def _refresh_volumes(self, volumes: list[dict]) -> list[dict]:
        """Re-read volume states after instance termination (attachments may have cleared)."""
        if not volumes:
            return []
        try:
            fresh = {v["VolumeId"]: v["State"] for v in self.ec2.describe_volumes(
                VolumeIds=[v["id"] for v in volumes])["Volumes"]}
        except Exception:
            return volumes
        return [{**v, "state": fresh[v["id"]]} for v in volumes if v["id"] in fresh]


def describe(found: dict[str, list[dict]]) -> list[str]:
    """Human-readable lines for everything found."""
    lines = []
    for kind, items in found.items():
        for item in items:
            extra = " ".join(str(item[k]) for k in ("state", "public_ip") if item.get(k))
            lines.append(f"  {kind:<16} {item['id']:<24} {item.get('name', '')} {extra}".rstrip())
    return lines


def reset(clients: AwsClients, settings: Settings, yes: bool = False, include_recycle_rule: bool = False,
          out: Callable[[str], None] = print, waiter_delay: int = 5) -> dict[str, list[dict]]:
    """List (and with yes=True delete) all warden:demo=true resources. Returns what was found."""
    found = find_demo_resources(clients, include_recycle_rule)
    out(f"Warden demo reset in {settings.region} - only resources tagged {DEMO_TAG[0]}={DEMO_TAG[1]}")
    lines = describe(found)
    if not lines:
        out("  nothing to delete")
    elif not yes:
        out("Would delete (dry run; pass --yes to delete):")
        for line in lines:
            out(line)
    else:
        out("Deleting:")
        Resetter(clients, out, waiter_delay).run(found)
    if not include_recycle_rule:
        out("Recycle Bin rule kept (pass --include-recycle-rule to delete the demo rule).")
    out("Note: snapshots already in the Recycle Bin expire on their own after 7 days.")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--yes", action="store_true", help="actually delete (default: dry run)")
    parser.add_argument("--include-recycle-rule", action="store_true",
                        help="also delete the Recycle Bin rule tagged warden:demo=true")
    args = parser.parse_args()
    settings = load_settings()
    reset(AwsClients(settings), settings, yes=args.yes, include_recycle_rule=args.include_recycle_rule)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main))
