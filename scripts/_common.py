"""Shared helpers for the demo scripts (preflight, plant, reset). Read-only helpers only."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

try:  # the package is installed editable under `uv run`; fall back to src/ otherwise
    import warden  # noqa: F401
except ImportError:  # pragma: no cover - only when run outside the venv
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from warden.aws import _BOTO_CONFIG, AwsClients  # noqa: E402
from warden.config import DEMO_TAG, TAG_RECYCLE, TAG_RECYCLE_VALUE  # noqa: E402
from warden.policy import tags_to_dict  # noqa: E402

AL2023_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
DEMO_FILTER = [{"Name": f"tag:{DEMO_TAG[0]}", "Values": [DEMO_TAG[1]]}]


def extra_client(clients: AwsClients, service: str) -> Any:
    """A client for a service AwsClients does not expose (ssm, iam)."""
    return clients.session.client(service, region_name=clients.settings.region, config=_BOTO_CONFIG)


def is_demo(tag_list: list[dict] | None) -> bool:
    """True only if the resource carries warden:demo=true (exact key, case-insensitive value)."""
    return tags_to_dict(tag_list).get(DEMO_TAG[0], "").strip().lower() == DEMO_TAG[1]


def demo_tags(name: str | None = None, **extra: str) -> list[dict[str, str]]:
    """Tag list with warden:demo=true, an optional Name, and extra key/values."""
    tags = {DEMO_TAG[0]: DEMO_TAG[1], **extra}
    if name:
        tags["Name"] = name
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def default_subnet(clients: AwsClients) -> dict | None:
    """Default-for-AZ subnet of the default VPC in the first AZ (sorted by name), or None."""
    vpcs = clients.ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        return None
    subnets = clients.ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}]
    )["Subnets"]
    available = [s for s in subnets if s.get("State", "available") == "available"]
    preferred = [s for s in available if s.get("DefaultForAz")] or available
    return sorted(preferred, key=lambda s: s["AvailabilityZone"])[0] if preferred else None


def resolve_al2023_ami(clients: AwsClients) -> tuple[str | None, str]:
    """(ami_id, source) for the latest AL2023 x86_64 AMI: SSM public parameter, else describe_images."""
    try:
        value = extra_client(clients, "ssm").get_parameter(Name=AL2023_PARAM)["Parameter"]["Value"]
        if value:
            return value, "ssm"
    except Exception:  # fall back below
        pass
    try:
        images = clients.ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
    except Exception:
        return None, "none"
    if not images:
        return None, "none"
    newest = max(images, key=lambda i: i.get("CreationDate", ""))
    return newest["ImageId"], "describe_images"


def rule_covers_recycle_tag(rule: dict) -> bool:
    """True if a Recycle Bin rule retains snapshots tagged warden:recycle=true."""
    if rule.get("Status", "available") not in ("available", "enabled", None):
        return False
    tags = rule.get("ResourceTags") or []
    if not tags:
        excluded = rule.get("ExcludeResourceTags") or []
        return not any(t.get("ResourceTagKey") == TAG_RECYCLE for t in excluded)
    return any(
        t.get("ResourceTagKey") == TAG_RECYCLE
        and (t.get("ResourceTagValue") or "").lower() == TAG_RECYCLE_VALUE
        for t in tags
    )


def list_snapshot_rules(clients: AwsClients) -> list[dict]:
    """All EBS_SNAPSHOT Recycle Bin rules with details (get_rule). Raises on access errors."""
    summaries: list[dict] = []
    kwargs: dict[str, Any] = {"ResourceType": "EBS_SNAPSHOT"}
    while True:
        page = clients.rbin.list_rules(**kwargs)
        summaries.extend(page.get("Rules", []))
        token = page.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    rules: list[dict] = []
    for summary in summaries:
        try:
            detail = clients.rbin.get_rule(Identifier=summary["Identifier"])
            detail.pop("ResponseMetadata", None)
            rules.append({**summary, **detail})
        except Exception:  # without details we cannot tell which tags it covers
            continue
    return rules


def find_warden_rule(clients: AwsClients) -> dict | None:
    """The first Recycle Bin rule that keeps warden:recycle=true snapshots, or None. Raises on errors."""
    return next((r for r in list_snapshot_rules(clients) if rule_covers_recycle_tag(r)), None)


def run_main(main: Callable[[], int]) -> int:
    """Run a script's main(); turn AWS/config failures into a clear one-line message and exit code 2."""
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, NoRegionError

    try:
        return main()
    except NoCredentialsError:
        print("ERROR: no AWS credentials found. Configure them (aws configure / AWS_PROFILE / SSO) and rerun.",
              file=sys.stderr)
    except NoRegionError:
        print("ERROR: no AWS region set. Set AWS_REGION in .env and rerun.", file=sys.stderr)
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "Unknown")
        print(f"ERROR: AWS refused the request ({code}): {err}. Check credentials and iam/warden-policy.json.",
              file=sys.stderr)
    except BotoCoreError as err:
        print(f"ERROR: could not reach AWS: {err}", file=sys.stderr)
    except ValueError as err:
        print(f"ERROR: invalid configuration: {err}", file=sys.stderr)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
    return 2
