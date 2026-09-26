"""Mutating actions. Every public function returns a receipt; per-item failures never raise.

Plan-gated flow: freeze check -> plan.validate_request -> for each approved id:
re-describe -> scope + policy recheck -> fingerprint compare -> act -> verify -> result.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from botocore.exceptions import ClientError, WaiterError

from . import audit as audit_mod
from . import plan as plan_mod
from . import policy, pricing
from .aws import AwsClients, error_code
from .config import (
    TAG_BACKUP_OF,
    TAG_EXPIRES_AT,
    TAG_PLAN_ID,
    TAG_RECYCLE,
    TAG_RECYCLE_VALUE,
    TAG_RECYCLED_AT,
    TAG_RESTORE_AZ,
    TAG_RESTORE_IOPS,
    TAG_RESTORE_SIZE,
    TAG_RESTORE_THROUGHPUT,
    TAG_RESTORE_TYPE,
    TAG_RESTORED_FROM,
    TAG_STOPPED_AT,
    Settings,
)

FROZEN_DETAIL = "Warden is frozen (WARDEN_FREEZE=true)"
MAX_TAGS_PER_RESOURCE = 50

# Warden bookkeeping tags: stripped when restoring so the restored resource looks like the original.
BOOKKEEPING_TAGS = frozenset(
    {
        TAG_BACKUP_OF, TAG_EXPIRES_AT, TAG_PLAN_ID, TAG_RECYCLE, TAG_RECYCLED_AT, TAG_STOPPED_AT,
        TAG_RESTORE_AZ, TAG_RESTORE_TYPE, TAG_RESTORE_SIZE, TAG_RESTORE_IOPS, TAG_RESTORE_THROUGHPUT,
        TAG_RESTORED_FROM,
    }
)

# (result, est_monthly_usd saved)
Outcome = tuple[dict, float]
Actor = Callable[[AwsClients, Settings, str, str, dict], Outcome]


# ---------------------------------------------------------------- small helpers


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _result(
    resource_id: str,
    status: str,
    detail: str,
    undo: dict | None = None,
    backup_snapshot_id: str | None = None,
    public_ip: str | None = None,
) -> dict:
    return {
        "resource_id": resource_id,
        "status": status,
        "detail": detail,
        "undo": undo,
        "backup_snapshot_id": backup_snapshot_id,
        "public_ip": public_ip,
    }


def _skipped(resource_id: str, detail: str, **kw: Any) -> Outcome:
    return _result(resource_id, "skipped", detail, **kw), 0.0


def _failed(resource_id: str, detail: str, **kw: Any) -> Outcome:
    return _result(resource_id, "failed", detail, **kw), 0.0


def _requested(ids: Any) -> list[str]:
    """Requested ids as display strings (deduped), or ['*'] when nothing usable was given."""
    raw = ids if isinstance(ids, (list, tuple)) else ([ids] if ids else [])
    out: list[str] = []
    for rid in raw:
        text = str(rid).strip() if rid is not None else ""
        if text and text not in out:
            out.append(text)
    return out or ["*"]


def _is_not_found(err: Exception) -> bool:
    code = error_code(err)
    return code.endswith("NotFound") or code.endswith(".Malformed")


def _account(clients: AwsClients) -> str:
    try:
        return clients.account_id()
    except Exception:  # noqa: BLE001 - STS failure must not crash the tool
        return "unknown"


def _to_aws_tags(tags: dict[str, str]) -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def _new_receipt(clients: AwsClients, settings: Settings, action: str, plan_id: str | None) -> dict:
    return {
        "receipt_id": audit_mod.new_id("rcpt"),
        "action": action,
        "plan_id": plan_id,
        "account_id": _account(clients),
        "region": settings.region,
        "started_at": audit_mod.iso_now(),
        "finished_at": None,
        "freeze": settings.freeze,
        "results": [],
        "counts": {"done": 0, "skipped": 0, "failed": 0},
        "est_monthly_savings_usd": 0.0,
    }


def _finish(settings: Settings, receipt: dict, outcomes: list[Outcome]) -> dict:
    """Fill counts/savings, persist the receipt and write audit lines."""
    results = [r for r, _ in outcomes]
    receipt["results"] = results
    receipt["counts"] = {s: sum(1 for r in results if r["status"] == s) for s in ("done", "skipped", "failed")}
    receipt["est_monthly_savings_usd"] = round(
        sum(saved for r, saved in outcomes if r["status"] == "done"), 2
    )
    receipt["finished_at"] = audit_mod.iso_now()
    for r in results:
        audit_mod.audit(
            settings,
            "action_item",
            receipt_id=receipt["receipt_id"],
            action=receipt["action"],
            plan_id=receipt["plan_id"],
            resource_id=r["resource_id"],
            status=r["status"],
            detail=r["detail"],
        )
    try:
        audit_mod.save_receipt(settings, receipt)
    except OSError as err:
        receipt["save_error"] = f"receipt not persisted: {err}"
    audit_mod.audit(
        settings,
        "action",
        receipt_id=receipt["receipt_id"],
        action=receipt["action"],
        plan_id=receipt["plan_id"],
        account_id=receipt["account_id"],
        region=receipt["region"],
        counts=receipt["counts"],
        est_monthly_savings_usd=receipt["est_monthly_savings_usd"],
    )
    return receipt


def _safe(actor: Callable[[], Outcome], resource_id: str) -> Outcome:
    """Run one per-item step; any unexpected error becomes a 'failed' result."""
    try:
        return actor()
    except Exception as err:  # noqa: BLE001 - never raise for per-item failures
        return _failed(resource_id, f"AWS error: {error_code(err)}: {err}")


# ---------------------------------------------------------------- describers (None = gone)


def _describe_volume(clients: AwsClients, volume_id: str) -> dict | None:
    try:
        vols = clients.ec2.describe_volumes(VolumeIds=[volume_id]).get("Volumes") or []
    except ClientError as err:
        if _is_not_found(err):
            return None
        raise
    return vols[0] if vols else None


def _describe_snapshot(clients: AwsClients, snapshot_id: str) -> dict | None:
    try:
        snaps = clients.ec2.describe_snapshots(SnapshotIds=[snapshot_id]).get("Snapshots") or []
    except ClientError as err:
        if _is_not_found(err):
            return None
        raise
    return snaps[0] if snaps else None


def _describe_instance(clients: AwsClients, instance_id: str) -> dict | None:
    try:
        resp = clients.ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as err:
        if _is_not_found(err):
            return None
        raise
    for reservation in resp.get("Reservations") or []:
        for inst in reservation.get("Instances") or []:
            if inst.get("InstanceId") == instance_id:
                if (inst.get("State") or {}).get("Name") == "terminated":
                    return None
                return inst
    return None


def _describe_address(clients: AwsClients, allocation_id: str) -> dict | None:
    try:
        addrs = clients.ec2.describe_addresses(AllocationIds=[allocation_id]).get("Addresses") or []
    except ClientError as err:
        if _is_not_found(err):
            return None
        raise
    return addrs[0] if addrs else None


_DESCRIBERS: dict[str, Callable[[AwsClients, str], dict | None]] = {
    "volume": _describe_volume,
    "snapshot": _describe_snapshot,
    "instance": _describe_instance,
    "address": _describe_address,
}


# ---------------------------------------------------------------- plan-gated flow


def _recheck(
    clients: AwsClients, settings: Settings, item: plan_mod.PlanItem
) -> tuple[dict | None, Outcome | None]:
    """Re-describe and re-run policy. Returns (resource, None) if still safe, else (None, skip outcome)."""
    rid = item.resource_id
    resource = _DESCRIBERS[item.resource_type](clients, rid)
    if resource is None:
        return None, _skipped(rid, "no longer exists")
    tags = policy.tags_to_dict(resource.get("Tags"))
    if not policy.in_scope(tags, settings):
        return None, _skipped(rid, f"changed since approval: no longer in scope ({settings.scope_label})")
    reasons = policy.keep_reasons(tags)
    if reasons:
        return None, _skipped(rid, "changed since approval: " + "; ".join(reasons))
    if plan_mod.fingerprint(item.resource_type, resource) != item.fingerprint:
        return None, _skipped(rid, "changed since approval (state or tags differ from the plan); re-scan and re-approve")
    return resource, None


def _run_gated(
    clients: AwsClients,
    settings: Settings,
    action: str,
    plan_id: str,
    resource_ids: Any,
    actor: Actor,
    preflight: Callable[[], str | None] | None = None,
) -> dict:
    """Shared freeze -> validate -> recheck -> act loop for plan-gated actions."""
    receipt = _new_receipt(clients, settings, action, plan_id if isinstance(plan_id, str) else None)
    requested = _requested(resource_ids)
    if settings.freeze:
        return _finish(settings, receipt, [_skipped(rid, FROZEN_DETAIL) for rid in requested])

    ids = list(resource_ids) if isinstance(resource_ids, (list, tuple)) else resource_ids
    plan, approved, rejected = plan_mod.validate_request(
        plan_id, action, ids, settings, receipt["account_id"], settings.region
    )
    if "*" in rejected:
        return _finish(settings, receipt, [_skipped(rid, rejected["*"]) for rid in requested])

    outcomes: list[Outcome] = [_skipped(rid, reason) for rid, reason in rejected.items()]
    blocker = preflight() if (preflight and approved) else None
    for rid in approved:
        if blocker:
            outcomes.append(_skipped(rid, blocker))
            continue
        item = plan.items[rid]

        def step(item: plan_mod.PlanItem = item) -> Outcome:
            resource, skip = _recheck(clients, settings, item)
            if skip:
                return skip
            return actor(clients, settings, plan.plan_id, item.resource_id, resource)

        outcomes.append(_safe(step, rid))
    return _finish(settings, receipt, outcomes)


# ---------------------------------------------------------------- quarantine volume


def _backup_tags(volume: dict, settings: Settings, plan_id: str, now: datetime) -> dict[str, str]:
    """Original (copyable, non-bookkeeping) tags + Warden restore metadata, within the 50-tag limit."""
    original = {
        k: v
        for k, v in policy.copyable_tags(policy.tags_to_dict(volume.get("Tags"))).items()
        if k not in BOOKKEEPING_TAGS
    }
    warden = {
        TAG_BACKUP_OF: volume["VolumeId"],
        TAG_EXPIRES_AT: _utc_iso(now + timedelta(days=settings.backup_retention_days)),
        TAG_RESTORE_AZ: str(volume.get("AvailabilityZone") or ""),
        TAG_RESTORE_TYPE: str(volume.get("VolumeType") or ""),
        TAG_RESTORE_SIZE: str(volume.get("Size") or ""),
        TAG_PLAN_ID: plan_id,
    }
    if volume.get("Iops") is not None:
        warden[TAG_RESTORE_IOPS] = str(volume["Iops"])
    if volume.get("Throughput") is not None:
        warden[TAG_RESTORE_THROUGHPUT] = str(volume["Throughput"])
    room = MAX_TAGS_PER_RESOURCE - len(warden)
    kept = dict(list(original.items())[:room])
    return {**kept, **warden}


def _volume_cost(volume: dict, settings: Settings) -> float:
    return pricing.volume_monthly_usd(
        str(volume.get("VolumeType") or "gp2"),
        int(volume.get("Size") or 0),
        volume.get("Iops"),
        volume.get("Throughput"),
        region=settings.region,
    )


def _quarantine_one(clients: AwsClients, settings: Settings, plan_id: str, vol_id: str, volume: dict) -> Outcome:
    ec2 = clients.ec2
    if volume.get("State") != "available" or volume.get("Attachments"):
        return _skipped(vol_id, f"changed since approval: volume is {volume.get('State')} / attached; kept")
    backup_tags = _backup_tags(volume, settings, plan_id, datetime.now(timezone.utc))
    snap = ec2.create_snapshot(
        VolumeId=vol_id,
        Description=f"Warden backup of {vol_id} before deletion (plan {plan_id})",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": _to_aws_tags(backup_tags)}],
    )
    snap_id = snap["SnapshotId"]
    try:
        ec2.get_waiter("snapshot_completed").wait(
            SnapshotIds=[snap_id],
            WaiterConfig={"Delay": 5, "MaxAttempts": max(1, settings.snapshot_wait_seconds // 5)},
        )
    except WaiterError as err:
        return _skipped(
            vol_id,
            f"backup not complete; volume kept (snapshot {snap_id} still pending after "
            f"{settings.snapshot_wait_seconds}s: {err})",
            backup_snapshot_id=snap_id,
        )
    latest = _describe_volume(clients, vol_id)
    if latest is None:
        return _skipped(vol_id, "no longer exists (disappeared during backup)", backup_snapshot_id=snap_id)
    if latest.get("State") != "available" or latest.get("Attachments"):
        return _skipped(vol_id, "volume was attached during backup; volume kept", backup_snapshot_id=snap_id)
    undo = {"tool": "restore_volume", "args": {"backup_snapshot_id": snap_id}}
    try:
        ec2.delete_volume(VolumeId=vol_id)
    except ClientError as err:
        return _failed(vol_id, f"backup {snap_id} completed but delete failed: {error_code(err)}", backup_snapshot_id=snap_id)
    after = _describe_volume(clients, vol_id)
    if after is not None and after.get("State") not in ("deleting", "deleted"):
        return _failed(
            vol_id, f"delete issued but volume is still {after.get('State')}", undo=undo, backup_snapshot_id=snap_id
        )
    detail = f"backed up to {snap_id} (completed) then deleted; restorable until {backup_tags[TAG_EXPIRES_AT]}"
    return _result(vol_id, "done", detail, undo=undo, backup_snapshot_id=snap_id), _volume_cost(volume, settings)


def quarantine_volumes(clients: AwsClients, settings: Settings, plan_id: str, volume_ids: list[str]) -> dict:
    """Back up each approved unused volume to a completed snapshot, then delete it. Reversible."""
    return _run_gated(clients, settings, "quarantine_volume", plan_id, volume_ids, _quarantine_one)


# ---------------------------------------------------------------- snapshots


def _recycle_bin_ready(clients: AwsClients) -> bool:
    """Scanner owns the rule check; import lazily so this module stays import-safe."""
    try:
        from .scanner import recycle_bin_ready
    except ImportError:
        return False
    try:
        return bool(recycle_bin_ready(clients))
    except Exception:  # noqa: BLE001
        return False


def _in_recycle_bin(clients: AwsClients, snapshot_id: str) -> bool:
    """True/False from the Recycle Bin listing; raises if the API is unavailable."""
    resp = clients.ec2.list_snapshots_in_recycle_bin(SnapshotIds=[snapshot_id])
    return any(s.get("SnapshotId") == snapshot_id for s in resp.get("Snapshots") or [])


def _recycle_one(clients: AwsClients, settings: Settings, plan_id: str, snap_id: str, snap: dict) -> Outcome:
    ec2 = clients.ec2
    ec2.create_tags(
        Resources=[snap_id],
        Tags=[
            {"Key": TAG_RECYCLE, "Value": TAG_RECYCLE_VALUE},
            {"Key": TAG_RECYCLED_AT, "Value": audit_mod.iso_now()},
            {"Key": TAG_PLAN_ID, "Value": plan_id},
        ],
    )
    try:
        ec2.delete_snapshot(SnapshotId=snap_id)
    except ClientError as err:
        try:
            ec2.delete_tags(Resources=[snap_id], Tags=[{"Key": TAG_RECYCLE}, {"Key": TAG_RECYCLED_AT}, {"Key": TAG_PLAN_ID}])
        except ClientError:
            pass
        return _failed(snap_id, f"delete failed (snapshot kept): {error_code(err)}")
    saved = pricing.snapshot_monthly_usd(int(snap.get("VolumeSize") or 0), region=settings.region)
    undo = {"tool": "restore_snapshot", "args": {"snapshot_id": snap_id}}
    try:
        found = _in_recycle_bin(clients, snap_id)
    except Exception as err:  # noqa: BLE001 - API may be unavailable (permissions, emulators)
        detail = f"moved to Recycle Bin; verification unavailable ({error_code(err)})"
        return _result(snap_id, "done", detail, undo=undo), saved
    if not found:
        return _failed(snap_id, "deleted but NOT found in Recycle Bin - may be unrecoverable; check rbin rules")
    return _result(snap_id, "done", "moved to Recycle Bin (verified); restorable via restore_snapshot", undo=undo), saved


def recycle_snapshots(clients: AwsClients, settings: Settings, plan_id: str, snapshot_ids: list[str]) -> dict:
    """Tag and delete snapshots into the Recycle Bin (retention rule required). Reversible."""

    def preflight() -> str | None:
        if _recycle_bin_ready(clients):
            return None
        return "Recycle Bin rule missing - use delete_snapshot_permanently after explicit approval"

    return _run_gated(clients, settings, "recycle_snapshot", plan_id, snapshot_ids, _recycle_one, preflight)


def _delete_snapshot_one(clients: AwsClients, settings: Settings, plan_id: str, snap_id: str, snap: dict) -> Outcome:
    try:
        clients.ec2.delete_snapshot(SnapshotId=snap_id)
    except ClientError as err:
        return _failed(snap_id, f"delete failed (snapshot kept): {error_code(err)}")
    if _describe_snapshot(clients, snap_id) is not None:
        return _failed(snap_id, "delete issued but snapshot still exists")
    saved = pricing.snapshot_monthly_usd(int(snap.get("VolumeSize") or 0), region=settings.region)
    return _result(snap_id, "done", "permanently deleted (IRREVERSIBLE; no Recycle Bin copy)"), saved


def delete_snapshot_permanently(clients: AwsClients, settings: Settings, plan_id: str, snapshot_id: str) -> dict:
    """Permanently delete exactly one snapshot. IRREVERSIBLE."""
    return _run_gated(clients, settings, "delete_snapshot", plan_id, [snapshot_id], _delete_snapshot_one)


# ---------------------------------------------------------------- instances


def _stop_one(clients: AwsClients, settings: Settings, plan_id: str, inst_id: str, inst: dict) -> Outcome:
    if inst.get("InstanceLifecycle") == "spot":
        return _skipped(inst_id, "spot instance; not stopped")
    if inst.get("RootDeviceType") == "instance-store":
        return _skipped(inst_id, "instance-store root device (data would be lost); not stopped")
    ec2 = clients.ec2
    ec2.stop_instances(InstanceIds=[inst_id])
    latest = _describe_instance(clients, inst_id)
    state = ((latest or {}).get("State") or {}).get("Name")
    undo = {"tool": "start_instances", "args": {"instance_ids": [inst_id]}}
    if state not in ("stopping", "stopped"):
        return _failed(inst_id, f"stop issued but instance is {state}", undo=undo)
    detail = f"stopped (state {state}); EBS volumes and data kept"
    try:
        ec2.create_tags(
            Resources=[inst_id],
            Tags=[{"Key": TAG_STOPPED_AT, "Value": audit_mod.iso_now()}, {"Key": TAG_PLAN_ID, "Value": plan_id}],
        )
    except ClientError as err:
        detail += f"; WARNING could not tag {TAG_STOPPED_AT} ({error_code(err)}) - start it manually"
    saved = pricing.instance_monthly_usd(str(inst.get("InstanceType") or ""), region=settings.region) or 0.0
    return _result(inst_id, "done", detail, undo=undo), saved


def stop_instances(clients: AwsClients, settings: Settings, plan_id: str, instance_ids: list[str]) -> dict:
    """Stop idle instances (never terminate). Reversible via start_instances."""
    return _run_gated(clients, settings, "stop_instance", plan_id, instance_ids, _stop_one)


# ---------------------------------------------------------------- addresses


def _release_one(clients: AwsClients, settings: Settings, plan_id: str, alloc_id: str, addr: dict) -> Outcome:
    ip = addr.get("PublicIp")
    if addr.get("AssociationId") or addr.get("InstanceId") or addr.get("NetworkInterfaceId"):
        return _skipped(alloc_id, "address is now associated; not released", public_ip=ip)
    try:
        clients.ec2.release_address(AllocationId=alloc_id)
    except ClientError as err:
        return _failed(alloc_id, f"release failed (address kept): {error_code(err)}", public_ip=ip)
    if _describe_address(clients, alloc_id) is not None:
        return _failed(alloc_id, "release issued but address still allocated", public_ip=ip)
    detail = (
        f"released {ip} (IRREVERSIBLE). Recovery is only possible via allocate_address(Address='{ip}') "
        "if nobody else has taken it; update DNS records and allow-lists."
    )
    return _result(alloc_id, "done", detail, public_ip=ip), pricing.address_monthly_usd(settings.region)


def release_address(clients: AwsClients, settings: Settings, plan_id: str, allocation_id: str) -> dict:
    """Release exactly one unassociated Elastic IP. IRREVERSIBLE."""
    return _run_gated(clients, settings, "release_address", plan_id, [allocation_id], _release_one)


# ---------------------------------------------------------------- undo tools (no plan)


def _check_ids(ids: Any, limit: int) -> tuple[list[str], str | None]:
    """Explicit, non-wildcard, deduped ids within limit; else (requested, reason)."""
    if not isinstance(ids, (list, tuple)) or not ids:
        return _requested(ids), "resource ids must be a non-empty list"
    clean: list[str] = []
    for rid in ids:
        if not isinstance(rid, str) or not rid.strip():
            return _requested(ids), "every resource id must be a non-empty string"
        rid = rid.strip()
        if rid.lower() in plan_mod.WILDCARDS or "*" in rid:
            return _requested(ids), f"wildcard id {rid!r} is not allowed; list explicit ids"
        if rid not in clean:
            clean.append(rid)
    if len(clean) > limit:
        return clean, f"batch of {len(clean)} exceeds the limit of {limit}"
    return clean, None


def _run_simple(
    clients: AwsClients, settings: Settings, action: str, ids: Any, limit: int, actor: Callable[[str], Outcome]
) -> dict:
    receipt = _new_receipt(clients, settings, action, None)
    if settings.freeze:
        return _finish(settings, receipt, [_skipped(rid, FROZEN_DETAIL) for rid in _requested(ids)])
    clean, problem = _check_ids(ids, limit)
    if problem:
        return _finish(settings, receipt, [_skipped(rid, problem) for rid in clean])
    return _finish(settings, receipt, [_safe(lambda rid=rid: actor(rid), rid) for rid in clean])


def _restore_volume_one(clients: AwsClients, settings: Settings, snap_id: str) -> Outcome:
    snap = _describe_snapshot(clients, snap_id)
    if snap is None:
        return _skipped(snap_id, "backup snapshot not found")
    tags = policy.tags_to_dict(snap.get("Tags"))
    source = tags.get(TAG_BACKUP_OF)
    if not source:
        return _skipped(snap_id, f"not a Warden backup (no {TAG_BACKUP_OF} tag); refusing to restore")
    if snap.get("State") != "completed":
        return _skipped(snap_id, f"backup snapshot is {snap.get('State')}, not completed")
    az = tags.get(TAG_RESTORE_AZ)
    if not az:
        return _failed(snap_id, f"backup is missing {TAG_RESTORE_AZ}; cannot pick an Availability Zone")
    vtype = tags.get(TAG_RESTORE_TYPE) or "gp3"
    kwargs: dict[str, Any] = {"AvailabilityZone": az, "SnapshotId": snap_id, "VolumeType": vtype}
    size = tags.get(TAG_RESTORE_SIZE, "")
    if size.isdigit():
        kwargs["Size"] = int(size)
    iops = tags.get(TAG_RESTORE_IOPS, "")
    if iops.isdigit() and vtype in ("gp3", "io1", "io2"):
        kwargs["Iops"] = int(iops)
    throughput = tags.get(TAG_RESTORE_THROUGHPUT, "")
    if throughput.isdigit() and vtype == "gp3":
        kwargs["Throughput"] = int(throughput)
    original = {k: v for k, v in policy.copyable_tags(tags).items() if k not in BOOKKEEPING_TAGS}
    original[TAG_RESTORED_FROM] = snap_id
    kwargs["TagSpecifications"] = [{"ResourceType": "volume", "Tags": _to_aws_tags(original)}]
    new_vol = clients.ec2.create_volume(**kwargs)["VolumeId"]
    check = _describe_volume(clients, new_vol)
    if check is None:
        return _failed(snap_id, f"create_volume returned {new_vol} but it cannot be described")
    detail = f"restored {source} as {new_vol} in {az} ({vtype}, state {check.get('State')}); attach it where needed"
    return _result(snap_id, "done", detail, backup_snapshot_id=snap_id), 0.0


def restore_volume(clients: AwsClients, settings: Settings, backup_snapshot_id: str) -> dict:
    """Recreate a quarantined volume from its Warden backup snapshot (original AZ, type, tags)."""
    return _run_simple(
        clients, settings, "restore_volume", [backup_snapshot_id], 1,
        lambda sid: _restore_volume_one(clients, settings, sid),
    )


def _recycled_by_warden(settings: Settings, snapshot_id: str) -> bool:
    """True if a Warden receipt shows this snapshot was recycled successfully."""
    for summary in audit_mod.list_receipts(settings, limit=100_000):
        if summary.get("action") != "recycle_snapshot":
            continue
        receipt = audit_mod.load_receipt(settings, str(summary.get("receipt_id"))) or {}
        for r in receipt.get("results") or []:
            if r.get("resource_id") == snapshot_id and r.get("status") == "done":
                return True
    return False


def _restore_snapshot_one(clients: AwsClients, settings: Settings, snap_id: str) -> Outcome:
    if not _recycled_by_warden(settings, snap_id):
        return _skipped(snap_id, "not recycled by Warden (no matching receipt); refusing to restore")
    try:
        in_bin = _in_recycle_bin(clients, snap_id)
    except Exception as err:  # noqa: BLE001
        return _failed(snap_id, f"Recycle Bin API unavailable: {error_code(err)}")
    if not in_bin:
        return _skipped(snap_id, "not in the Recycle Bin (retention may have expired)")
    clients.ec2.restore_snapshot_from_recycle_bin(SnapshotId=snap_id)
    detail = "restored from Recycle Bin"
    try:
        clients.ec2.delete_tags(Resources=[snap_id], Tags=[{"Key": TAG_RECYCLE}, {"Key": TAG_RECYCLED_AT}])
    except ClientError as err:
        detail += f"; WARNING could not remove {TAG_RECYCLE} tag ({error_code(err)})"
    if _describe_snapshot(clients, snap_id) is None:
        detail += "; snapshot not yet visible in describe_snapshots (restores can take a moment)"
    return _result(snap_id, "done", detail), 0.0


def restore_snapshot(clients: AwsClients, settings: Settings, snapshot_id: str) -> dict:
    """Restore a snapshot that Warden moved to the Recycle Bin."""
    return _run_simple(
        clients, settings, "restore_snapshot", [snapshot_id], 1,
        lambda sid: _restore_snapshot_one(clients, settings, sid),
    )


def _start_one(clients: AwsClients, settings: Settings, inst_id: str) -> Outcome:
    inst = _describe_instance(clients, inst_id)
    if inst is None:
        return _skipped(inst_id, "no longer exists")
    tags = policy.tags_to_dict(inst.get("Tags"))
    if TAG_STOPPED_AT not in tags:
        return _skipped(inst_id, f"not stopped by Warden (no {TAG_STOPPED_AT} tag); refusing to start")
    state = (inst.get("State") or {}).get("Name")
    if state != "stopped":
        return _skipped(inst_id, f"instance is {state}, not stopped; try again shortly")
    clients.ec2.start_instances(InstanceIds=[inst_id])
    latest = _describe_instance(clients, inst_id)
    new_state = ((latest or {}).get("State") or {}).get("Name")
    if new_state not in ("pending", "running"):
        return _failed(inst_id, f"start issued but instance is {new_state}")
    detail = f"started (state {new_state})"
    try:
        clients.ec2.delete_tags(Resources=[inst_id], Tags=[{"Key": TAG_STOPPED_AT}])
    except ClientError as err:
        detail += f"; WARNING could not remove {TAG_STOPPED_AT} ({error_code(err)})"
    return _result(inst_id, "done", detail), 0.0


def start_instances(clients: AwsClients, settings: Settings, instance_ids: list[str]) -> dict:
    """Start instances that Warden stopped (tagged warden:stopped-at). Batch up to max_batch."""
    return _run_simple(
        clients, settings, "start_instances", instance_ids, settings.max_batch,
        lambda iid: _start_one(clients, settings, iid),
    )
