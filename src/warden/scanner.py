"""Read-only waste scanner: builds findings, locks them into a Plan, never mutates AWS."""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import pricing
from .audit import audit, quarantine_problem, record_quarantine_void
from .aws import AwsClients, dry_run, error_code
from .config import (
    TAG_BACKUP_OF,
    TAG_EXPIRES_AT,
    TAG_HUMAN_UNDO_AT,
    TAG_QUARANTINED_UNTIL,
    TAG_RECYCLE,
    TAG_RECYCLE_VALUE,
    TAG_RESTORED_FROM,
    Settings,
)
from .plan import ACTIONS, PlanItem, fingerprint, new_plan, save_plan
from .policy import in_scope, keep_reasons, sanitize_tags, tags_to_dict

LEAK_PROBLEM = (
    "DeleteOnTermination=false: every instance launched from this template leaves this disk behind "
    "when terminated"
)
NO_METRICS_REASON = "no CloudWatch data yet for the lookback window"
INSTANCE_STORE_REASON = "has instance-store volumes whose data is lost on stop - a human must confirm"
# An idle verdict needs this many CPU and network datapoints, and at least half of those the window should have.
MIN_IDLE_DATAPOINTS = 3
MIN_IDLE_COVERAGE = 0.5
HUMAN_UNDO_PREFIX = "a human undid Warden's action here"
NO_OWNER_NOTE = "no CloudTrail event in the last 90 days (events can take up to 15 minutes to appear)"
# Boot, cloud-init and user-data make a new instance look busy; ignore this long after launch.
BOOT_WARMUP_MINUTES = 10
# The README promises a 7-day undo for recycled snapshots; shorter rules do not count.
RECYCLE_MIN_RETENTION_DAYS = 7
_CREATE_EVENTS = ("Create", "Run", "Allocate", "Copy", "Import", "Register")
UNTAGGED_PROD_REASON = "name suggests production but it is not tagged - a human must confirm"
# prod/prd/production/live as a whole word; "_" and "-" count as separators (my_prod_db, prod-eu).
_PROD_NAME = re.compile(r"(?<![A-Za-z0-9])(?:prod|prd|production|live)(?![A-Za-z0-9])", re.IGNORECASE)
_ENV_TAG_KEYS = {"env", "environment", "stage"}
_THROTTLE_CODES = {"Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException"}
_clock = time.monotonic  # patched in tests
DECISION_LIST_MAX = 10


# --------------------------------------------------------------------------- helpers


def _paginate(client: Any, method: str, key: str, **kwargs: Any) -> list[dict]:
    """Collect every item under `key` across pages (falls back to one call)."""
    if client.can_paginate(method):
        out: list[dict] = []
        for page in client.get_paginator(method).paginate(**kwargs):
            out.extend(page.get(key) or [])
        return out
    return list(getattr(client, method)(**kwargs).get(key) or [])


def _iso(value: Any) -> str | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_days(value: Any, now: datetime) -> float | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return round((now - value).total_seconds() / 86400, 1)


def _parse_time(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def countdown(seconds: float) -> str:
    """Human countdown such as '6d 23h 10m' ('expired' at or below zero)."""
    if seconds <= 0:
        return "expired"
    minutes = max(1, math.ceil(seconds / 60))
    days, rest = divmod(minutes, 1440)
    hours, mins = divmod(rest, 60)
    parts = [f"{days}d"] if days else []
    if days or hours:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts)


def _finding(
    resource_type: str,
    resource_id: str,
    raw: dict,
    tags: dict[str, str],
    settings: Settings,
    now: datetime,
    *,
    state: str | None,
    created: Any = None,
    az: str | None = None,
    size_gib: int | None = None,
) -> dict:
    """Skeleton finding with safe defaults (verdict filled in by the caller)."""
    clean = sanitize_tags(tags)
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "name": clean.get("Name"),
        "region": settings.region,
        "availability_zone": az,
        "size_gib": size_gib,
        "state": state,
        "created_at": _iso(created),
        "age_days": _age_days(created, now),
        "tags": clean,
        "verdict": "keep",
        "action": None,
        "reversible": None,
        "reasons": [],
        "warnings": [],
        "evidence": {"references": [], "activity": None, "owner": None, "dry_run": "not run", "leak": None},
        "est_monthly_usd": None,
        "fingerprint": fingerprint(resource_type, raw),
    }


def _set_verdict(finding: dict, verdict: str, reasons: list[str], action: str | None = None) -> dict:
    finding["verdict"] = verdict
    finding["reasons"] = list(reasons)
    finding["action"] = action if verdict == "act" else None
    finding["reversible"] = ACTIONS[action].reversible if verdict == "act" and action else None
    return finding


# --------------------------------------------------------------------------- recycle bin


def _tag_matches(rule_tag: dict, tags: dict[str, str]) -> bool:
    key = rule_tag.get("ResourceTagKey")
    if key not in tags:
        return False
    want = rule_tag.get("ResourceTagValue")
    return want in (None, "") or tags[key] == want


def _retention_days(rule: dict) -> int:
    period = rule.get("RetentionPeriod") or {}
    if str(period.get("RetentionPeriodUnit", "")).upper() != "DAYS":
        return 0
    try:
        return int(period.get("RetentionPeriodValue") or 0)
    except (TypeError, ValueError):
        return 0


def rule_covers(rule: dict, tags: dict[str, str] | None = None) -> bool:
    """True if this rule would keep a snapshot with these tags once Warden adds warden:recycle=true.

    Tag-level rules keep a snapshot carrying any of their ResourceTags. Region-level rules keep every
    snapshot except those matching one of their ExcludeResourceTags. Retention must be >= 7 days.
    """
    if str(rule.get("Status", "")).lower() != "available":
        return False
    if _retention_days(rule) < RECYCLE_MIN_RETENTION_DAYS:
        return False
    effective = {**(tags or {}), TAG_RECYCLE: TAG_RECYCLE_VALUE}
    included = rule.get("ResourceTags") or []
    if included:
        return any(_tag_matches(t, effective) for t in included)
    return not any(_tag_matches(t, effective) for t in rule.get("ExcludeResourceTags") or [])


def recycle_rules(clients: AwsClients) -> list[dict]:
    """Available EBS_SNAPSHOT Recycle Bin rules that keep warden:recycle=true snapshots ([] on any error)."""
    rules: list[dict] = []
    try:
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = {"ResourceType": "EBS_SNAPSHOT"}
            if token:
                kwargs["NextToken"] = token
            page = clients.rbin.list_rules(**kwargs)
            for summary in page.get("Rules") or []:
                rule = clients.rbin.get_rule(Identifier=summary["Identifier"])
                if rule_covers(rule):
                    rules.append(rule)
            token = page.get("NextToken")
            if not token:
                return rules
    except Exception:  # AccessDenied, not implemented, network...
        return []


def recycle_bin_ready(clients: AwsClients) -> bool:
    """True when an available Recycle Bin rule keeps snapshots tagged warden:recycle=true."""
    return bool(recycle_rules(clients))


# --------------------------------------------------------------------------- evidence context


@dataclass
class _Context:
    """Evidence gathered once per scan (never scope-filtered)."""

    templates: list[dict] = field(default_factory=list)  # launch template versions
    template_tags: dict[str, dict[str, str]] = field(default_factory=dict)  # template id -> its own tags
    leak_sources: list[dict] = field(default_factory=list)
    snapshot_to_amis: dict[str, list[dict]] = field(default_factory=dict)
    snapshot_to_templates: dict[str, list[dict]] = field(default_factory=dict)
    ami_to_templates: dict[str, list[dict]] = field(default_factory=dict)
    ami_to_instances: dict[str, list[str]] = field(default_factory=dict)
    volume_ids: set[str] = field(default_factory=set)
    leaks: dict[tuple, dict] = field(default_factory=dict)
    # First error code while listing volumes, AMIs or launch templates: what uses a snapshot is then unknown.
    snapshot_evidence_error: str | None = None

    def evidence_failed(self, err: Exception) -> str:
        code = error_code(err)
        if self.snapshot_evidence_error is None:
            self.snapshot_evidence_error = code
        return code


def _load_templates(clients: AwsClients, ctx: _Context, notes: list[str]) -> list[dict]:
    versions: list[dict] = []
    try:
        templates = _paginate(clients.ec2, "describe_launch_templates", "LaunchTemplates")
    except Exception as err:
        notes.append(f"launch templates unavailable ({ctx.evidence_failed(err)}); leak detection skipped")
        return versions
    for tpl in templates:
        tid = tpl.get("LaunchTemplateId")
        ctx.template_tags[str(tid)] = tags_to_dict(tpl.get("Tags"))
        try:
            resp = clients.ec2.describe_launch_template_versions(
                LaunchTemplateId=tid, Versions=["$Default", "$Latest"]
            )
        except Exception as err:
            notes.append(f"{tid}: could not read template versions ({ctx.evidence_failed(err)})")
            continue
        seen: set[int] = set()
        for ver in resp.get("LaunchTemplateVersions") or []:
            number = int(ver.get("VersionNumber") or 0)
            if number not in seen:
                seen.add(number)
                versions.append(ver)
    return versions


def _leak_sources(versions: list[dict]) -> list[dict]:
    sources: list[dict] = []
    for ver in versions:
        data = ver.get("LaunchTemplateData") or {}
        vol_tags: dict[str, str] = {}
        for spec in data.get("TagSpecifications") or []:
            if spec.get("ResourceType") == "volume":
                vol_tags.update(tags_to_dict(spec.get("Tags")))
        for bdm in data.get("BlockDeviceMappings") or []:
            ebs = bdm.get("Ebs") or {}
            if ebs.get("DeleteOnTermination") is False:
                sources.append(
                    {
                        "template_id": ver.get("LaunchTemplateId"),
                        "template_name": ver.get("LaunchTemplateName"),
                        "version": int(ver.get("VersionNumber") or 0),
                        "device": bdm.get("DeviceName"),
                        "ebs": ebs,
                        "volume_tags": vol_tags,
                    }
                )
    return sources


def _index_template_snapshots(ctx: _Context) -> None:
    """snapshot id -> launch template versions whose block devices create a disk from it."""
    for ver in ctx.templates:
        for bdm in (ver.get("LaunchTemplateData") or {}).get("BlockDeviceMappings") or []:
            snap = (bdm.get("Ebs") or {}).get("SnapshotId")
            if snap:
                ctx.snapshot_to_templates.setdefault(snap, []).append({
                    "id": ver.get("LaunchTemplateId"),
                    "name": ver.get("LaunchTemplateName"),
                    "version": int(ver.get("VersionNumber") or 0),
                    "device": bdm.get("DeviceName"),
                })


def _load_amis(clients: AwsClients, ctx: _Context, notes: list[str]) -> None:
    try:
        images = _paginate(clients.ec2, "describe_images", "Images", Owners=["self"])
    except Exception as err:
        notes.append(f"AMIs unavailable ({ctx.evidence_failed(err)}); snapshots are held for review")
        return
    for image in images:
        ref = {"id": image.get("ImageId"), "name": sanitize_tags({"n": image.get("Name") or ""})["n"]}
        for bdm in image.get("BlockDeviceMappings") or []:
            snap = (bdm.get("Ebs") or {}).get("SnapshotId")
            if snap:
                ctx.snapshot_to_amis.setdefault(snap, []).append(ref)
    for ver in ctx.templates:
        ami = (ver.get("LaunchTemplateData") or {}).get("ImageId")
        if ami:
            ref = {"id": ver.get("LaunchTemplateId"), "name": ver.get("LaunchTemplateName")}
            if ref not in ctx.ami_to_templates.setdefault(ami, []):
                ctx.ami_to_templates[ami].append(ref)


def _all_instances(clients: AwsClients, notes: list[str]) -> list[dict]:
    try:
        reservations = _paginate(clients.ec2, "describe_instances", "Reservations")
    except Exception as err:
        notes.append(f"instances unavailable ({error_code(err)})")
        return []
    return [inst for res in reservations for inst in res.get("Instances") or []]


def _build_context(clients: AwsClients, instances: list[dict], notes: list[str]) -> _Context:
    ctx = _Context()
    ctx.templates = _load_templates(clients, ctx, notes)
    ctx.leak_sources = _leak_sources(ctx.templates)
    _index_template_snapshots(ctx)
    _load_amis(clients, ctx, notes)
    for inst in instances:
        if (inst.get("State") or {}).get("Name") in ("terminated", "shutting-down"):
            continue
        if inst.get("ImageId"):
            ctx.ami_to_instances.setdefault(inst["ImageId"], []).append(inst["InstanceId"])
    try:
        ctx.volume_ids = {v["VolumeId"] for v in _paginate(clients.ec2, "describe_volumes", "Volumes")}
    except Exception as err:
        notes.append(f"could not list all volumes ({ctx.evidence_failed(err)}); snapshots are held for review")
    return ctx


def _instance_storage(clients: AwsClients, types: Iterable[str]) -> tuple[dict[str, bool], str | None]:
    """{instance type: has instance-store volumes} for these types in one call (per 100 types), and the
    error code if the lookup failed (then the map is empty and callers must fail closed)."""
    wanted = sorted({t for t in types if t})
    out: dict[str, bool] = {}
    try:
        for i in range(0, len(wanted), 100):
            kwargs: dict[str, Any] = {"InstanceTypes": wanted[i:i + 100]}
            while True:
                resp = clients.ec2.describe_instance_types(**kwargs)
                for info in resp.get("InstanceTypes") or []:
                    out[str(info.get("InstanceType"))] = bool(info.get("InstanceStorageSupported"))
                if not resp.get("NextToken"):
                    break
                kwargs["NextToken"] = resp["NextToken"]
    except Exception as err:
        return {}, error_code(err)
    return out, None


def _human_undo_reasons(resource_type: str, tags: dict[str, str], created: Any = None) -> list[str]:
    """A human undid Warden's action on this resource (undo tools tag it): never propose it again.

    Every undo tool writes warden:human-undo-at; volumes restored from a Warden backup also carry
    warden:restored-from (older restores carry only that one)."""
    lower = {str(k).strip().lower(): v for k, v in sanitize_tags(tags).items()}
    present = [TAG_HUMAN_UNDO_AT] if TAG_HUMAN_UNDO_AT in lower else []
    if resource_type == "volume" and TAG_RESTORED_FROM in lower:
        present.append(TAG_RESTORED_FROM)
    if not present:
        return []
    when = str(lower.get(TAG_HUMAN_UNDO_AT) or "").strip()[:40] or _iso(created) or "date unknown"
    noun = "tag" if len(present) == 1 else "tags"
    return [f"{HUMAN_UNDO_PREFIX} ({when}); Warden will not propose it again. "
            f"Remove the {' and '.join(present)} {noun} to allow"]


# --------------------------------------------------------------------------- relationships (DNS, load balancers)


def _dns_index(clients: AwsClients) -> dict[str, list[str]]:
    """public IP -> ["<record> (<type>) in zone <zone>"] for every A/AAAA record (raises on API errors)."""
    index: dict[str, list[str]] = {}
    r53 = clients.route53
    for zone in _paginate(r53, "list_hosted_zones", "HostedZones"):
        zone_name = str(zone.get("Name") or "").rstrip(".")
        records = _paginate(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zone["Id"])
        for rec in records:
            if rec.get("Type") not in ("A", "AAAA"):
                continue
            label = f"{str(rec.get('Name') or '').rstrip('.')} ({rec['Type']}) in zone {zone_name}"
            for value in rec.get("ResourceRecords") or []:
                ip = str(value.get("Value") or "").strip()
                if ip and label not in index.setdefault(ip, []):
                    index[ip].append(label)
    return index


def dns_index(clients: AwsClients, *, strict: bool = False) -> dict[str, list[str]]:
    """Every Route 53 A/AAAA value -> records, built once ({} on any error, unless strict=True: then it raises)."""
    try:
        return _dns_index(clients)
    except Exception:  # AccessDenied, throttling, network...
        if strict:
            raise
        return {}


def dns_references(clients: AwsClients, public_ip: str, *, strict: bool = False) -> list[str]:
    """Route 53 A/AAAA records whose value is public_ip ([] on any error, unless strict=True: then it raises)."""
    return list(dns_index(clients, strict=strict).get(str(public_ip).strip(), []))


def _private_ip_index(clients: AwsClients) -> dict[str, str]:
    """private IP -> instance id for every non-terminated instance (raises on API errors)."""
    out: dict[str, str] = {}
    for res in _paginate(clients.ec2, "describe_instances", "Reservations"):
        for inst in res.get("Instances") or []:
            if (inst.get("State") or {}).get("Name") == "terminated":
                continue
            ips = {inst.get("PrivateIpAddress")}
            for eni in inst.get("NetworkInterfaces") or []:
                ips.update(p.get("PrivateIpAddress") for p in eni.get("PrivateIpAddresses") or [])
            out.update({ip: inst["InstanceId"] for ip in ips if ip})
    return out


def _lb_index(clients: AwsClients) -> dict[str, list[str]]:
    """instance id -> [target group names] for instance- and ip-type target groups (raises on API errors).
    ip-type targets are mapped to instances through their private IPs."""
    out: dict[str, list[str]] = {}
    by_ip: dict[str, str] | None = None
    for tg in _paginate(clients.elbv2, "describe_target_groups", "TargetGroups"):
        ttype = tg.get("TargetType", "instance")
        if ttype not in ("instance", "ip"):
            continue
        name = tg.get("TargetGroupName") or tg.get("TargetGroupArn")
        health = clients.elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
        for desc in health.get("TargetHealthDescriptions") or []:
            target = (desc.get("Target") or {}).get("Id")
            if target and ttype == "ip":
                if by_ip is None:
                    by_ip = _private_ip_index(clients)
                target = by_ip.get(target)
            if target and name not in out.setdefault(target, []):
                out[target].append(name)
    return out


def lb_target_instances(clients: AwsClients, *, strict: bool = False) -> dict[str, list[str]]:
    """Instances registered in an ELBv2 target group ({} on any error, unless strict=True: then it raises)."""
    try:
        return _lb_index(clients)
    except Exception:
        if strict:
            raise
        return {}


def _has_env_tag(tags: dict[str, str]) -> bool:
    return any(str(k).strip().lower() in _ENV_TAG_KEYS and str(v).strip() for k, v in tags.items())


def _prod_guard(finding: dict | None, raw: dict) -> dict | None:
    """Untagged-production heuristic: a production-looking Name (or snapshot Description) with no env tag
    turns act/review into review. Never overrides a keep."""
    if finding is None or finding["verdict"] == "keep":
        return finding
    tags = tags_to_dict(raw.get("Tags"))
    if _has_env_tag(tags):
        return finding
    texts = [tags.get("Name") or "", str(raw.get("Description") or "")]
    if not any(_PROD_NAME.search(t) for t in texts):
        return finding
    reasons = [UNTAGGED_PROD_REASON] + [r for r in finding["reasons"] if r != UNTAGGED_PROD_REASON]
    return _set_verdict(finding, "review", reasons)


# --------------------------------------------------------------------------- volumes


def _match_leak(volume: dict, tags: dict[str, str], ctx: _Context) -> dict | None:
    matches = []
    for src in ctx.leak_sources:
        by_id = tags.get("aws:ec2launchtemplate:id") == src["template_id"]
        wanted = src["volume_tags"]
        by_tags = bool(wanted) and all(tags.get(k) == v for k, v in wanted.items())
        if by_id or by_tags:
            matches.append(src)
    if not matches:
        return None
    sized = [m for m in matches if m["ebs"].get("VolumeSize") == volume.get("Size")]
    return (sized or matches)[0]


def _leak_record(src: dict, region: str) -> dict:
    ebs = {**src["ebs"], "DeleteOnTermination": True}
    data = json.dumps({"BlockDeviceMappings": [{"DeviceName": src["device"], "Ebs": ebs}]}, separators=(",", ":"))
    return {
        "launch_template_id": src["template_id"],
        "launch_template_name": src["template_name"],
        "version": src["version"],
        "device_name": src["device"],
        "orphaned_volume_ids": [],
        "problem": LEAK_PROBLEM,
        "fix": f"Create a new template version with DeleteOnTermination=true for {src['device']}",
        "fix_cli": (
            f"aws ec2 create-launch-template-version --launch-template-id {src['template_id']} "
            f"--source-version {src['version']} --launch-template-data '{data}' --region {region}"
        ),
    }


def _standing_leaks(ctx: _Context, settings: Settings) -> None:
    """Leaky templates in scope are reported even with no orphan right now (orphaned_volume_ids []), so the
    leak does not vanish from the report once its disks are cleaned up. One record per template + device."""
    reported = {(leak["launch_template_id"], leak["device_name"]) for leak in ctx.leaks.values()}
    for src in ctx.leak_sources:
        if (src["template_id"], src["device"]) in reported:
            continue
        if not in_scope(ctx.template_tags.get(str(src["template_id"]), {}), settings):
            continue
        reported.add((src["template_id"], src["device"]))
        ctx.leaks[(src["template_id"], src["version"], src["device"])] = _leak_record(src, settings.region)


def _volume_finding(vol: dict, settings: Settings, ctx: _Context, now: datetime) -> dict | None:
    tags = tags_to_dict(vol.get("Tags"))
    if not in_scope(tags, settings):
        return None
    vid = vol["VolumeId"]
    f = _finding(
        "volume", vid, vol, tags, settings, now,
        state=vol.get("State"), created=vol.get("CreateTime"),
        az=vol.get("AvailabilityZone"), size_gib=vol.get("Size"),
    )
    vtype = vol.get("VolumeType") or "gp2"
    f["est_monthly_usd"] = pricing.volume_monthly_usd(
        vtype, vol.get("Size") or 0, vol.get("Iops"), vol.get("Throughput"), settings.region
    )
    if vtype == "gp2":
        f["warnings"].append("gp2 is ~20% pricier than gp3")
    if vol.get("Encrypted"):
        f["warnings"].append(
            f"encrypted with KMS key {vol.get('KmsKeyId') or '(account default)'}: restore_volume needs the "
            "Warden identity to be allowed to use this key through EBS (see iam/README.md)"
        )
    src = _match_leak(vol, tags, ctx)
    if src is not None:
        key = (src["template_id"], src["version"], src["device"])
        leak = ctx.leaks.setdefault(key, _leak_record(src, settings.region))
        leak["orphaned_volume_ids"].append(vid)
        f["evidence"]["leak"] = leak
        f["evidence"]["references"].append(
            f"{vid} <- launch template {src['template_id']} ({src['template_name']}) v{src['version']} "
            f"{src['device']} with DeleteOnTermination=false"
        )
    reasons = keep_reasons(tags) + _human_undo_reasons("volume", tags, vol.get("CreateTime"))
    if reasons:
        return _set_verdict(f, "keep", reasons)
    return _set_verdict(
        f, "act", ["unattached (status available): paying for storage nobody uses"], "quarantine_volume"
    )


# --------------------------------------------------------------------------- snapshots


def _ami_chain(snap_id: str, ctx: _Context) -> list[str]:
    chains = []
    for ami in ctx.snapshot_to_amis.get(snap_id, []):
        chain = f"{snap_id} -> {ami['id']} ({ami['name']})"
        templates = ctx.ami_to_templates.get(ami["id"], [])
        if templates:
            chain += " -> " + ", ".join(f"launch template {t['id']} ({t['name']})" for t in templates)
        running = ctx.ami_to_instances.get(ami["id"], [])
        if running:
            chain += " -> instances " + ", ".join(running)
        chains.append(chain)
    return chains


def _is_shared(clients: AwsClients, snap_id: str) -> bool:
    resp = clients.ec2.describe_snapshot_attribute(SnapshotId=snap_id, Attribute="createVolumePermission")
    return bool(resp.get("CreateVolumePermissions"))


def _snapshot_finding(
    clients: AwsClients, snap: dict, settings: Settings, ctx: _Context, now: datetime, rules: list[dict]
) -> dict | None:
    tags = tags_to_dict(snap.get("Tags"))
    if not in_scope(tags, settings):
        return None
    sid = snap["SnapshotId"]
    size = snap.get("VolumeSize")
    f = _finding(
        "snapshot", sid, snap, tags, settings, now,
        state=snap.get("State"), created=snap.get("StartTime"), size_gib=size,
    )
    f["est_monthly_usd"] = pricing.snapshot_monthly_usd(size or 0, settings.region)
    f["warnings"].append("cost is an upper bound: snapshots bill on stored changed blocks")
    source = snap.get("VolumeId")
    if source:
        f["evidence"]["references"].append(f"source volume {source}")

    reasons = keep_reasons(tags) + _human_undo_reasons("snapshot", tags, snap.get("StartTime"))
    if reasons:
        return _set_verdict(f, "keep", reasons)
    chains = _ami_chain(sid, ctx)
    if chains:
        f["evidence"]["references"].extend(chains)
        return _set_verdict(
            f, "keep", [f"used by AMI: {c}; autoscaling/launches would break" for c in chains]
        )
    templates = ctx.snapshot_to_templates.get(sid, [])
    if templates:
        f["evidence"]["references"].extend(
            f"{sid} -> launch template {t['id']} ({t['name']}) v{t['version']} {t['device']}" for t in templates
        )
        labels = list(dict.fromkeys(f"{t['name']} ({t['id']})" for t in templates))
        return _set_verdict(f, "keep", [f"used by launch template {label}; launches would fail" for label in labels])
    if snap.get("State") != "completed":
        return _set_verdict(f, "keep", [f"snapshot is {snap.get('State')}, not completed"])
    if _is_shared(clients, sid):
        return _set_verdict(f, "keep", ["shared with other accounts"])

    backup_of = tags.get(TAG_BACKUP_OF)
    act_reason: str
    if backup_of:
        expires = _parse_time(tags.get(TAG_EXPIRES_AT))
        if expires is None:
            return _set_verdict(f, "review", [f"Warden backup of {backup_of} without a valid {TAG_EXPIRES_AT} tag"])
        if expires > now:
            return _set_verdict(
                f, "keep", [f"Warden backup of {backup_of}, restorable until {_iso(expires)}"]
            )
        act_reason = f"expired Warden backup of {backup_of} (expired {_iso(expires)})"
    elif source and source != "vol-ffffffff" and source in ctx.volume_ids:
        return _set_verdict(f, "keep", ["source volume still exists - may be its backup"])
    else:
        act_reason = "orphan: source volume is gone and no AMI uses it"
    if ctx.snapshot_evidence_error is not None:  # fail closed: a user of this snapshot may have been missed
        return _set_verdict(f, "review", [f"could not verify what uses this snapshot: {ctx.snapshot_evidence_error}"])

    if any(rule_covers(rule, tags) for rule in rules):
        return _set_verdict(f, "act", [act_reason, "Recycle Bin keeps it restorable"], "recycle_snapshot")
    if rules:
        f["warnings"].append(
            "Irreversible: the Recycle Bin rule excludes this snapshot's tags, so deletion is permanent "
            "(one id per call)"
        )
    else:
        f["warnings"].append(
            "Irreversible: no Recycle Bin rule for warden:recycle=true, so deletion is permanent (one id per call)"
        )
    return _set_verdict(f, "act", [act_reason], "delete_snapshot")


# --------------------------------------------------------------------------- instances


def metric_period(lookback_minutes: int) -> int:
    """Period (seconds): >=300, at most 1440 datapoints, and the multiple CloudWatch requires for the
    start time's age (60 s up to 15 days, 300 s up to 63 days, 3600 s beyond)."""
    needed = math.ceil(lookback_minutes * 60 / 1440)
    step = 3600 if lookback_minutes > 63 * 1440 else 300 if lookback_minutes > 15 * 1440 else 60
    return max(300, math.ceil(needed / step) * step)


def _metric(
    clients: AwsClients, instance_id: str, name: str, stat: str, start: datetime, end: datetime, period: int
) -> list[float]:
    resp = clients.cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName=name,
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start,
        EndTime=end,
        Period=period,
        Statistics=[stat],
    )
    return [float(dp[stat]) for dp in resp.get("Datapoints") or [] if stat in dp]


def _activity(
    clients: AwsClients,
    instance_id: str,
    settings: Settings,
    now: datetime,
    launched: Any = None,
    lookback_minutes: int | None = None,
) -> dict:
    """CPU/network over the lookback window, excluding the first BOOT_WARMUP_MINUTES after launch."""
    lookback = lookback_minutes or settings.idle_lookback_minutes
    start = now - timedelta(minutes=lookback)
    if isinstance(launched, datetime):
        if launched.tzinfo is None:
            launched = launched.replace(tzinfo=timezone.utc)
        start = max(start, launched + timedelta(minutes=BOOT_WARMUP_MINUTES))
    window_minutes = (now - start).total_seconds() / 60
    period = metric_period(max(5, math.ceil(window_minutes)))
    out: dict[str, Any] = {
        "lookback_minutes": lookback,
        "window_start": _iso(start),
        "observed_minutes": max(0, round(window_minutes)),
        "period_seconds": period,
        # Whole periods in the observed window: what full CloudWatch coverage would return.
        "expected_datapoints": max(1, int(window_minutes * 60 // period)),
        "datapoints": 0,
        "network_datapoints": 0,
        "max_cpu_pct": None,
        "network_bytes_per_hour": None,
        "idle_cpu_pct": settings.idle_cpu_pct,
        "idle_network_bytes_per_hour": settings.idle_network_bytes_per_hour,
    }
    if window_minutes < 5:
        out["note"] = f"launched less than {BOOT_WARMUP_MINUTES + 5} minutes ago; boot activity is not evidence"
        return out
    cpu = _metric(clients, instance_id, "CPUUtilization", "Maximum", start, now, period)
    net_in = _metric(clients, instance_id, "NetworkIn", "Sum", start, now, period)
    net_out = _metric(clients, instance_id, "NetworkOut", "Sum", start, now, period)
    # Divide by the time actually observed: datapoints exist only while the instance ran.
    observed_hours = max(len(net_in), len(net_out)) * period / 3600
    out["datapoints"] = len(cpu)
    out["network_datapoints"] = max(len(net_in), len(net_out))
    out["max_cpu_pct"] = round(max(cpu), 2) if cpu else None
    if observed_hours:
        out["network_bytes_per_hour"] = round((sum(net_in) + sum(net_out)) / observed_hours, 1)
    return out


def _stop_protected(clients: AwsClients, instance_id: str) -> bool:
    resp = clients.ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiStop")
    return bool((resp.get("DisableApiStop") or {}).get("Value"))


def _instance_store_problem(itype: str, storage: dict[str, bool] | None, storage_error: str | None) -> str | None:
    """Why stopping this type could lose data (instance-store volumes), or None. Unknown means a problem."""
    if storage_error is not None or storage is None or itype not in storage:
        why = storage_error or "type not described"
        return (f"could not check whether {itype or 'its instance type'} has instance-store volumes ({why}); "
                "their data is lost on stop - a human must confirm")
    return INSTANCE_STORE_REASON if storage[itype] else None


def _instance_finding(
    clients: AwsClients, inst: dict, settings: Settings, now: datetime,
    lb_targets: dict[str, list[str]] | None = None,
    storage: dict[str, bool] | None = None,
    storage_error: str | None = None,
) -> dict | None:
    """storage: {instance type: has instance-store volumes} from _instance_storage (None = not checked)."""
    tags = tags_to_dict(inst.get("Tags"))
    if not in_scope(tags, settings):
        return None
    iid = inst["InstanceId"]
    itype = inst.get("InstanceType") or ""
    f = _finding(
        "instance", iid, inst, tags, settings, now,
        state=(inst.get("State") or {}).get("Name"), created=inst.get("LaunchTime"),
        az=(inst.get("Placement") or {}).get("AvailabilityZone"),
    )
    f["est_monthly_usd"] = pricing.instance_monthly_usd(itype, settings.region)
    f["warnings"].append("savings cover compute only; attached EBS volumes keep billing while stopped")

    reasons = keep_reasons(tags) + _human_undo_reasons("instance", tags, inst.get("LaunchTime"))
    if reasons:
        return _set_verdict(f, "keep", reasons)
    groups = (lb_targets or {}).get(iid) or []
    if groups:
        f["evidence"]["references"].extend(f"{iid} <- load balancer target group {g}" for g in groups)
        return _set_verdict(
            f, "keep", [f"serving traffic via load balancer target group {', '.join(groups)}"]
        )
    if inst.get("InstanceLifecycle") == "spot":
        return _set_verdict(f, "keep", ["spot instance: stopping may lose capacity/request"])
    if inst.get("RootDeviceType") == "instance-store":
        return _set_verdict(f, "keep", ["instance-store root device: stopping is not possible"])
    if _stop_protected(clients, iid):
        return _set_verdict(f, "keep", ["stop protection (DisableApiStop) is enabled"])

    activity = _activity(clients, iid, settings, now, launched=inst.get("LaunchTime"))
    f["evidence"]["activity"] = activity
    cpu = activity["max_cpu_pct"]
    if cpu is None:
        return _set_verdict(f, "review", [NO_METRICS_REASON])
    net = activity["network_bytes_per_hour"] or 0.0
    if cpu >= settings.idle_cpu_pct or net >= settings.idle_network_bytes_per_hour:
        return _set_verdict(f, "keep", [f"active: max CPU {cpu}%, {net:,.0f} network bytes/hour"])
    # Idle so far - but "idle" must rest on enough evidence (thin or missing data fails closed).
    window = f"over the last {activity['observed_minutes']} minutes (since {activity['window_start']})"
    have = min(activity["datapoints"], activity["network_datapoints"])
    expected = activity["expected_datapoints"]
    if have < MIN_IDLE_DATAPOINTS or have < MIN_IDLE_COVERAGE * expected:
        return _set_verdict(f, "review", [f"not enough CloudWatch data: {have} of {expected} datapoints {window}"])
    problem = _instance_store_problem(itype, storage, storage_error)
    if problem:
        return _set_verdict(f, "review", [problem])
    return _set_verdict(
        f, "act", [f"idle: max CPU {cpu}% and {net:,.0f} network bytes/hour {window}"], "stop_instance"
    )


# --------------------------------------------------------------------------- addresses


def _address_finding(
    addr: dict, settings: Settings, now: datetime, dns: dict[str, list[str]] | None = None,
    dns_checked: bool = True,
) -> dict | None:
    """Unassociated Elastic IPs: quarantine first (reversible), release only after the window."""
    tags = tags_to_dict(addr.get("Tags"))
    if not addr.get("AllocationId") or not in_scope(tags, settings):
        return None
    if addr.get("AssociationId") or addr.get("InstanceId") or addr.get("NetworkInterfaceId"):
        if TAG_QUARANTINED_UNTIL in tags:  # someone still needs it: this quarantine can never justify a release
            record_quarantine_void(settings, addr["AllocationId"], tags, "seen associated by a scan")
        return None
    until_text = tags.get(TAG_QUARANTINED_UNTIL)
    state = "quarantined" if until_text is not None else "unassociated"
    f = _finding("address", addr["AllocationId"], addr, tags, settings, now, state=state)
    f["est_monthly_usd"] = pricing.address_monthly_usd(settings.region)
    ip = addr.get("PublicIp")
    f["evidence"]["references"].append(f"public IP {ip}")
    reasons = keep_reasons(tags) + _human_undo_reasons("address", tags)
    if reasons:
        return _set_verdict(f, "keep", reasons)
    records = (dns or {}).get(str(ip or "").strip(), [])
    if records:
        f["evidence"]["references"].extend(f"DNS {r} -> {ip}" for r in records)
        return _set_verdict(
            f, "keep",
            [f"DNS record {', '.join(records)} points at this IP - releasing would leave a dangling record "
             "(subdomain takeover risk)"],
        )
    if not dns_checked:
        return _set_verdict(f, "review", ["could not read Route 53 records, so DNS references to this IP are unknown"])
    if until_text is None:
        return _set_verdict(
            f, "act",
            [f"Elastic IP {ip} is not associated with anything; quarantine it first (tag only, reversible)"],
            "quarantine_address",
        )
    until = _parse_time(until_text)
    if until is None:
        return _set_verdict(f, "review", [f"invalid {TAG_QUARANTINED_UNTIL} tag {until_text!r}"])
    if until > now:
        return _set_verdict(
            f, "keep", [f"in quarantine - releasable in {countdown((until - now).total_seconds())}"]
        )
    problem = quarantine_problem(settings, addr["AllocationId"], tags, now=now)
    if problem:
        return _set_verdict(
            f, "act", [f"{problem}; quarantine it again for a fresh window (tag only, reversible)"],
            "quarantine_address",
        )
    f["warnings"].append(
        "Irreversible: this public IP cannot be guaranteed back; check partner allow-lists first (one id per call)"
    )
    return _set_verdict(
        f, "act",
        [f"Elastic IP {ip} finished its quarantine ({_iso(until)}) and is still not associated with anything"],
        "release_address",
    )


# --------------------------------------------------------------------------- enrichment


def _first_problem(*results: str) -> str:
    """'would_succeed' only if every step would succeed, else the first other result."""
    return next((r for r in results if r != "would_succeed"), "would_succeed")


def _dry_run_call(clients: AwsClients, finding: dict) -> str:
    rid, action = finding["resource_id"], finding["action"]
    ec2 = clients.ec2
    if action == "quarantine_volume":
        return _first_problem(dry_run(ec2.create_snapshot, VolumeId=rid), dry_run(ec2.delete_volume, VolumeId=rid))
    if action == "recycle_snapshot":
        return _first_problem(
            dry_run(ec2.create_tags, Resources=[rid], Tags=[{"Key": TAG_RECYCLE, "Value": TAG_RECYCLE_VALUE}]),
            dry_run(ec2.delete_snapshot, SnapshotId=rid),
        )
    if action == "delete_snapshot":
        return dry_run(ec2.delete_snapshot, SnapshotId=rid)
    if action == "stop_instance":
        return dry_run(ec2.stop_instances, InstanceIds=[rid])
    if action == "quarantine_address":
        probe = [{"Key": TAG_QUARANTINED_UNTIL, "Value": _iso(datetime.now(timezone.utc)) or ""}]
        return dry_run(ec2.create_tags, Resources=[rid], Tags=probe)
    if action == "release_address":
        return dry_run(ec2.release_address, AllocationId=rid)
    return "not run"


def _apply_dry_runs(clients: AwsClients, findings: list[dict]) -> None:
    for f in findings:
        if f["verdict"] != "act":
            continue
        result = _dry_run_call(clients, f)
        f["evidence"]["dry_run"] = result
        if result.startswith("denied"):
            _set_verdict(f, "review", f["reasons"] + [f"AWS dry run denied: {result.split(': ', 1)[-1]}"])
        elif result != "would_succeed":
            _set_verdict(f, "review", f["reasons"] + [f"AWS dry run did not confirm the action ({result})"])


def _lookup_owner(clients: AwsClients, resource_id: str) -> dict:
    try:
        resp = clients.cloudtrail.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": resource_id}], MaxResults=5
        )
    except Exception as err:
        return {"created_by": None, "note": f"owner lookup unavailable ({error_code(err)})",
                "_code": error_code(err)}
    events = resp.get("Events") or []
    if not events:
        return {"created_by": None, "note": NO_OWNER_NOTE}
    creates = [e for e in events if str(e.get("EventName", "")).startswith(_CREATE_EVENTS)]
    event = (creates or events)[-1]
    who = event.get("Username")
    if not who:
        try:
            who = json.loads(event.get("CloudTrailEvent") or "{}").get("userIdentity", {}).get("arn")
        except ValueError:
            who = None
    return {"created_by": who, "event": event.get("EventName"), "event_time": _iso(event.get("EventTime"))}


def _apply_owners(clients: AwsClients, findings: list[dict], settings: Settings, started: float) -> None:
    """CloudTrail creator per target, within the scan's time budget (owner lookups get half of it).
    A non-throttling failure (not implemented, access denied, 5xx...) stops further lookups for this scan."""
    cache: dict[str, dict] = {}
    skipped: dict | None = None
    order = [f for f in findings if f["verdict"] == "act"] + [f for f in findings if f["verdict"] == "review"]
    for f in order:
        rid = f["resource_id"]
        if rid not in cache:
            if len(cache) >= settings.owner_lookup_limit:
                break
            if skipped is None and _clock() - started > settings.scan_budget_seconds / 2:
                skipped = {"created_by": None, "note": "owner lookup skipped (time budget)"}
            if skipped is not None:
                cache[rid] = skipped
            else:
                owner = _lookup_owner(clients, rid)
                code = owner.pop("_code", None)
                if code is not None and code not in _THROTTLE_CODES:
                    skipped = {"created_by": None, "note": f"owner lookup skipped (CloudTrail unavailable: {code})"}
                cache[rid] = owner
        f["evidence"]["owner"] = cache[rid]


def _tier(finding: dict) -> str:
    if finding["verdict"] == "keep":
        return "protected"
    if finding["verdict"] == "act" and finding["reversible"]:
        return "safe_reversible"
    return "needs_review"


def _age_phrase(finding: dict) -> str:
    age = finding.get("age_days")
    if age is None:
        return ""
    if age < 1:
        return " less than a day ago"
    days = int(age)
    return f" {days} day{'s' if days != 1 else ''} ago"


def _why_act(finding: dict, settings: Settings) -> str:
    action = finding["action"]
    leak = finding["evidence"].get("leak")
    if action == "quarantine_volume" and leak:
        return (f"Left behind by launch template {leak['launch_template_name']} (DeleteOnTermination=false) and "
                "nothing uses it now; Warden will back it up first so you can restore it in one click.")
    if action == "quarantine_volume":
        return (f"Created{_age_phrase(finding)}, attached to nothing and nothing references it; Warden will back "
                "it up first so you can restore it in one click.")
    if action == "recycle_snapshot":
        what = ("Warden's own backup whose restore window has ended" if finding["tags"].get(TAG_BACKUP_OF)
                else "A snapshot of a disk that no longer exists and no image uses it")
        return f"{what}; it goes to the Recycle Bin, so you can still restore it for 7 days."
    if action == "delete_snapshot":
        return ("Nothing uses this snapshot, but there is no Recycle Bin safety net, so deleting it is permanent "
                "and it needs its own approval.")
    if action == "stop_instance":
        return ("It has barely used any CPU or network lately; stopping keeps its disks and you can start it "
                "again in one click.")
    if action == "quarantine_address":
        return (f"This public IP is attached to nothing and no DNS record points at it; Warden only marks it for a "
                f"{countdown(settings.quarantine_minutes * 60)} quarantine first and releases nothing yet.")
    if action == "release_address":
        return ("Its quarantine is over and it is still unused with no DNS record pointing at it; releasing is "
                "permanent because the same IP cannot be guaranteed back.")
    return "Warden found nothing that uses it."


def _why_review(finding: dict) -> str:
    reasons = finding["reasons"]
    if UNTAGGED_PROD_REASON in reasons:
        return ("Its name suggests production but it has no environment tag, so a human must confirm before "
                "anything happens.")
    if any(r.startswith("AWS dry run") for r in reasons):
        return "AWS did not confirm a dry run of the cleanup, so Warden will not act until a human checks access."
    if NO_METRICS_REASON in reasons:
        return "There is no usage data for it yet, so Warden cannot tell whether it is idle."
    if any(r.startswith("not enough CloudWatch data") for r in reasons):
        return "It looks idle, but there is too little usage data to be sure, so a human should decide."
    if INSTANCE_STORE_REASON in reasons:
        return ("It looks idle, but its instance-store disks lose their data when it stops, so a human must "
                "confirm first.")
    first = reasons[0] if reasons else "no clear evidence either way"
    return f"Warden cannot judge this safely on its own ({first}), so a human should decide."


def _why_keep(finding: dict) -> str:
    first = finding["reasons"][0] if finding["reasons"] else "no reason to act"
    if first.startswith("active:"):
        return "It is in active use, so Warden leaves it alone."
    if first.startswith("used by AMI"):
        return "A machine image (AMI) is built from this snapshot, so deleting it would break future launches."
    if first.startswith("used by launch template"):
        return "A launch template creates disks from this snapshot, so deleting it would make launches fail."
    if first.startswith(HUMAN_UNDO_PREFIX):
        return first[0].upper() + first[1:] + "."
    if first.startswith("protected: "):
        first = first[len("protected: "):]
    return f"Warden will not touch it: {first}."


def _apply_tiers(findings: list[dict], settings: Settings) -> None:
    """Add the human-facing tier and a one-sentence why to every finding."""
    for f in findings:
        f["tier"] = _tier(f)
        if f["verdict"] == "keep":
            f["why"] = _why_keep(f)
        elif f["verdict"] == "act":
            f["why"] = _why_act(f, settings)
        else:
            f["why"] = _why_review(f)


def _decision_list(findings: list[dict]) -> list[str]:
    """Up to DECISION_LIST_MAX ids: needs_review first, then safe_reversible, each by monthly cost desc."""
    def ordered(tier: str) -> list[dict]:
        group = [f for f in findings if _tier(f) == tier]
        return sorted(group, key=lambda f: f["est_monthly_usd"] or 0.0, reverse=True)

    return [f["resource_id"] for f in ordered("needs_review") + ordered("safe_reversible")][:DECISION_LIST_MAX]


def _summary(findings: list[dict]) -> dict:
    acts = [f for f in findings if f["verdict"] == "act"]
    tiers = [_tier(f) for f in findings]
    return {
        "act": len(acts),
        "keep": sum(f["verdict"] == "keep" for f in findings),
        "review": sum(f["verdict"] == "review" for f in findings),
        "reversible_actions": sum(bool(f["reversible"]) for f in acts),
        "irreversible_actions": sum(f["reversible"] is False for f in acts),
        "est_monthly_savings_usd": round(sum(f["est_monthly_usd"] or 0.0 for f in acts), 2),
        "tiers": {t: tiers.count(t) for t in ("safe_reversible", "needs_review", "protected")},
        "decision_list": _decision_list(findings),
    }


# --------------------------------------------------------------------------- scan


def _evaluate(
    kind: str, resources: Iterable[dict], id_key: str, build: Any, findings: list[dict], notes: list[str]
) -> None:
    """Run build(resource) for each resource, isolating failures into notes."""
    for res in resources:
        try:
            finding = build(res)
        except Exception as err:
            notes.append(f"{kind} {res.get(id_key, '?')}: could not evaluate ({error_code(err)}); skipped")
            continue
        if finding is not None:
            findings.append(finding)


def _list(kind: str, fn: Any, notes: list[str]) -> list[dict]:
    try:
        return fn()
    except Exception as err:
        notes.append(f"could not list {kind} ({error_code(err)}); {kind} skipped")
        return []


def scan(clients: AwsClients, settings: Settings, now: datetime | None = None) -> dict:
    """Scan one region for waste, save a Plan of every finding, and return the report."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    started = _clock()
    notes: list[str] = [f"prices are {pricing.PRICING_NOTE}"]
    account_id = clients.account_id()
    rules = recycle_rules(clients)
    rb_ready = bool(rules)
    if not rb_ready:
        notes.append(
            "Recycle Bin rule for warden:recycle=true not found: snapshot deletions would be permanent "
            "(delete_snapshot, one id per call)"
        )
    ec2 = clients.ec2
    all_instances = _all_instances(clients, notes)
    ctx = _build_context(clients, all_instances, notes)
    findings: list[dict] = []

    volumes = _list("volumes", lambda: _paginate(
        ec2, "describe_volumes", "Volumes", Filters=[{"Name": "status", "Values": ["available"]}]), notes)
    _evaluate(
        "volume", volumes, "VolumeId", lambda v: _prod_guard(_volume_finding(v, settings, ctx, now), v),
        findings, notes,
    )
    _standing_leaks(ctx, settings)

    snapshots = _list("snapshots", lambda: _paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]), notes)
    _evaluate(
        "snapshot", snapshots, "SnapshotId",
        lambda s: _prod_guard(_snapshot_finding(clients, s, settings, ctx, now, rules), s), findings, notes,
    )

    running = [i for i in all_instances if (i.get("State") or {}).get("Name") == "running"]
    lb_targets: dict[str, list[str]] = {}
    storage: dict[str, bool] = {}
    storage_error: str | None = None
    if running:
        try:
            lb_targets = _lb_index(clients)
        except Exception as err:
            notes.append(f"load balancer target groups unavailable ({error_code(err)}); "
                         "instances behind a load balancer may be misjudged")
        # One DescribeInstanceTypes call per scan for the distinct in-scope types (instance-store check).
        types = [i.get("InstanceType") or "" for i in running if in_scope(tags_to_dict(i.get("Tags")), settings)]
        storage, storage_error = _instance_storage(clients, types)
        if storage_error is not None:
            notes.append(f"instance types unavailable ({storage_error}); idle instances held for review "
                         "(instance-store data would be lost on stop)")
    _evaluate(
        "instance", running, "InstanceId",
        lambda i: _prod_guard(_instance_finding(clients, i, settings, now, lb_targets, storage, storage_error), i),
        findings, notes,
    )

    addresses = _list("addresses", lambda: _paginate(ec2, "describe_addresses", "Addresses"), notes)
    dns: dict[str, list[str]] = {}
    dns_checked = True
    if any(not a.get("AssociationId") for a in addresses):
        try:
            dns = _dns_index(clients)
        except Exception as err:
            dns_checked = False
            notes.append(f"Route 53 records unavailable ({error_code(err)}); unused Elastic IPs held for review")
    _evaluate(
        "address", addresses, "AllocationId",
        lambda a: _prod_guard(_address_finding(a, settings, now, dns, dns_checked), a), findings, notes,
    )

    _apply_dry_runs(clients, findings)
    _apply_owners(clients, findings, settings, started)
    _apply_tiers(findings, settings)

    items = [
        PlanItem(f["resource_id"], f["resource_type"], f["verdict"], f["action"], f["fingerprint"])
        for f in findings
    ]
    plan = new_plan(account_id, settings.region, items, settings)
    save_plan(plan, settings)
    summary = _summary(findings)
    # One compact row per finding, so resource_history can answer "was X scanned, and what was decided?".
    results = [
        {"resource_id": f["resource_id"], "resource_type": f["resource_type"], "name": f["name"],
         "verdict": f["verdict"], "tier": f["tier"], "action": f["action"],
         "reason": f["reasons"][0] if f["reasons"] else None}
        for f in findings
    ]
    audit(settings, "scan", plan_id=plan.plan_id, account_id=account_id, region=settings.region,
          scope=settings.scope_label, summary=summary, results=results)
    return {
        "plan_id": plan.plan_id,
        "account_id": account_id,
        "region": settings.region,
        "scope": settings.scope_label,
        "generated_at": _iso(now),
        "recycle_bin_ready": rb_ready,
        "summary": summary,
        "findings": findings,
        "leaks": list(ctx.leaks.values()),
        "notes": notes,
    }
