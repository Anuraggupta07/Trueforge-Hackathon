"""Warden preflight: read-only checks that the AWS account/region can run the demo.

Run: uv run python scripts/preflight.py
Never mutates anything (EC2 probes use DryRun). Always exits 0.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import _common
from _common import AwsClients, default_subnet, extra_client, find_warden_rule, resolve_al2023_ami, run_main
from warden.aws import dry_run, error_code
from warden.config import Settings, load_settings

OK, BLOCKED, WARN = "OK", "BLOCKED", "WARN"


def _row(check: str, status: str, detail: str, disables: str = "") -> dict[str, str]:
    return {"check": check, "status": status, "detail": detail, "disables": disables}


def _safe(check: str, disables: str, fn: Callable[[], dict[str, str]]) -> dict[str, str]:
    """Run one check; any exception becomes a BLOCKED row."""
    try:
        return fn()
    except Exception as err:
        return _row(check, BLOCKED, f"{error_code(err)}: {str(err)[:160]}", disables)


def _dry_run_row(check: str, result: str, disables: str) -> dict[str, str]:
    status = OK if result == "would_succeed" else BLOCKED
    return _row(check, status, f"DryRun -> {result}", "" if status == OK else disables)


def run_checks(clients: AwsClients, settings: Settings) -> list[dict[str, str]]:
    """Run every read-only check and return table rows."""
    rows: list[dict[str, str]] = []
    ctx: dict[str, Any] = {}

    def identity() -> dict[str, str]:
        who = clients.sts.get_caller_identity()
        return _row("STS identity", OK, f"account {who['Account']}  arn {who['Arn']}")

    rows.append(_safe("STS identity", "everything (no usable AWS credentials)", identity))

    def region() -> dict[str, str]:
        zones = clients.ec2.describe_availability_zones()["AvailabilityZones"]
        names = ", ".join(z["ZoneName"] for z in zones if z.get("State") == "available")
        return _row("Region", OK, f"{settings.region} (AZs: {names or 'none available'})")

    rows.append(_safe("Region", "all EC2 work in this region", region))

    def vpc() -> dict[str, str]:
        subnet = default_subnet(clients, "t3.micro")  # the instance type plant.py launches
        if subnet is None:
            return _row("Default VPC + subnet", BLOCKED, "no default VPC/subnet in an AZ offering t3.micro",
                        "plant.py (instances, launch-template leak demo)")
        ctx["subnet"] = subnet
        return _row("Default VPC + subnet", OK,
                    f"{subnet['VpcId']} / {subnet['SubnetId']} in {subnet['AvailabilityZone']} (offers t3.micro)")

    rows.append(_safe("Default VPC + subnet", "plant.py (instances, leak demo)", vpc))

    def ami() -> dict[str, str]:
        ami_id, source = resolve_al2023_ami(clients)
        if not ami_id:
            return _row("AL2023 AMI", BLOCKED, "SSM parameter and describe_images both failed",
                        "plant.py instances (idle server, leak demo)")
        ctx["ami"] = ami_id
        status = OK if source == "ssm" else WARN
        return _row("AL2023 AMI", status, f"{ami_id} (via {source})")

    rows.append(_safe("AL2023 AMI", "plant.py instances", ami))

    az = ctx.get("subnet", {}).get("AvailabilityZone") or f"{settings.region}a"
    rows.append(_dry_run_row(
        "EC2 create_volume",
        dry_run(clients.ec2.create_volume, AvailabilityZone=az, Size=1, VolumeType="gp3"),
        "plant.py volumes; quarantine restores (restore_volume)",
    ))
    if ctx.get("ami"):
        kwargs: dict[str, Any] = {"ImageId": ctx["ami"], "InstanceType": "t3.micro",
                                  "MinCount": 1, "MaxCount": 1}
        if ctx.get("subnet"):
            kwargs["SubnetId"] = ctx["subnet"]["SubnetId"]
        rows.append(_dry_run_row("EC2 run_instances t3.micro", dry_run(clients.ec2.run_instances, **kwargs),
                                 "plant.py idle server + launch-template leak demo"))
    else:
        rows.append(_row("EC2 run_instances t3.micro", BLOCKED, "skipped: no AMI",
                         "plant.py idle server + launch-template leak demo"))

    def rbin() -> dict[str, str]:
        rule = find_warden_rule(clients)
        if rule:
            return _row("Recycle Bin", OK, f"Warden rule present: {rule.get('Identifier')}")
        return _row("Recycle Bin", WARN, "access OK, Warden rule missing (plant.py creates it)",
                    "reversible recycle_snapshot until the rule exists")

    rows.append(_safe("Recycle Bin", "recycle_snapshot (snapshots fall back to one-by-one permanent delete)", rbin))

    def cloudtrail() -> dict[str, str]:
        clients.cloudtrail.lookup_events(MaxResults=1)
        return _row("CloudTrail lookup_events", OK, "readable")

    rows.append(_safe("CloudTrail lookup_events", "owner evidence (who created a resource)", cloudtrail))

    def cloudwatch() -> dict[str, str]:
        end = datetime.now(timezone.utc)
        clients.cloudwatch.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="CPUUtilization", StartTime=end - timedelta(hours=1),
            EndTime=end, Period=300, Statistics=["Maximum"],
        )
        return _row("CloudWatch metrics", OK, "readable")

    rows.append(_safe("CloudWatch metrics", "idle-instance detection (instances become 'review')", cloudwatch))

    def ssm() -> dict[str, str]:
        extra_client(clients, "ssm").get_parameter(Name=_common.AL2023_PARAM)
        return _row("SSM public parameter", OK, "readable")

    rows.append(_safe("SSM public parameter", "nothing critical (AMI falls back to describe_images)", ssm))

    def iam() -> dict[str, str]:
        extra_client(clients, "iam").get_account_summary()
        return _row("IAM read", OK, "get_account_summary readable")

    rows.append(_safe("IAM read", "only informs: IAM deny policy setup and Deep Inspect (roadmap)", iam))
    return rows


def render(rows: list[dict[str, str]]) -> str:
    """Format rows as a plain-text table plus a list of what BLOCKED items disable."""
    width = max(len(r["check"]) for r in rows)
    lines = [f"{'CHECK'.ljust(width)}  STATUS   DETAIL", "-" * (width + 60)]
    lines += [f"{r['check'].ljust(width)}  {r['status'].ljust(7)}  {r['detail']}" for r in rows]
    impacted = [r for r in rows if r["status"] != OK and r["disables"]]
    if impacted:
        lines += ["", "What the non-OK items disable:"]
        lines += [f"  - {r['check']} [{r['status']}]: {r['disables']}" for r in impacted]
    else:
        lines += ["", "All checks OK."]
    return "\n".join(lines)


def main() -> int:
    settings = load_settings()
    print(f"Warden preflight (read-only) - region {settings.region}, scope {settings.scope_label}\n")
    print(render(run_checks(AwsClients(settings), settings)))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main))
