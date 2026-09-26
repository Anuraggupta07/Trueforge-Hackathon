"""Watchdog: an independent verifier that must sign off before the Executor (actions.py) may act.

Deliberately a separate code path from actions.py (never imports it): it re-describes every resource
with its own boto3 calls, re-runs scope/policy/fingerprint checks plus action-specific safety checks,
and issues a short-lived, single-use HMAC token bound to (plan, action, approved ids, fingerprints).
It also reports the live rollback window. Every decision is recorded in the hash-chained ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import audit as audit_mod
from . import plan as plan_mod
from . import policy
from .aws import AwsClients, error_code
from .config import (
    TAG_BACKUP_OF,
    TAG_EXPIRES_AT,
    TAG_QUARANTINED_AT,
    TAG_QUARANTINED_UNTIL,
    TAG_STOPPED_AT,
    Settings,
    is_frozen,
)

FROZEN_REASON = "Warden is frozen (WARDEN_FREEZE=true or a FREEZE file in the state directory)"
KEY_FILE = "watchdog.key"
KEY_BYTES = 32
RECYCLE_FALLBACK_DAYS = 7
_SIGNOFF_ID = re.compile(r"^wd-[A-Za-z0-9-]+$")
_MAC = re.compile(r"^[0-9a-f]{64}$")
_KEY_LOCK = threading.Lock()


# ---------------------------------------------------------------- small helpers


def _now(now: float | None) -> float:
    return time.time() if now is None else float(now)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_epoch(value: Any) -> float | None:
    """ISO-8601 string or datetime -> epoch seconds, else None."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def countdown(seconds: float) -> str:
    """'6d 23h 10m', '2h 5m', '4m 12s' or 'expired'."""
    total = int(seconds)
    if total <= 0:
        return "expired"
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m {secs}s"


def _canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _requested(ids: Any) -> list[str]:
    raw = ids if isinstance(ids, (list, tuple)) else ([ids] if ids else [])
    out: list[str] = []
    for rid in raw:
        text = str(rid).strip() if rid is not None else ""
        if text and text not in out:
            out.append(text)
    return out or ["*"]


def _new_signoff_id() -> str:
    return f"wd-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _signoffs_dir(settings: Settings) -> Path:
    return settings.state_dir / "signoffs"


def _load_key(settings: Settings, create: bool) -> bytes | None:
    """The HMAC key at state_dir/watchdog.key (32 random bytes, created on first use)."""
    path = settings.state_dir / KEY_FILE
    with _KEY_LOCK:
        try:
            key = path.read_bytes()
            if len(key) == KEY_BYTES:
                return key
        except OSError:
            pass
        if not create:
            return None
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{KEY_FILE}.{uuid.uuid4().hex[:8]}.tmp")
        tmp.write_bytes(secrets.token_bytes(KEY_BYTES))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        try:
            os.link(tmp, path)  # fails if another process created the key first
        except FileExistsError:
            pass
        except OSError:
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()
        key = path.read_bytes()
        return key if len(key) == KEY_BYTES else None


def _mac(key: bytes, record: dict) -> str:
    return hmac.new(key, _canonical(record).encode("utf-8"), hashlib.sha256).hexdigest()


def _account(clients: AwsClients) -> str:
    try:
        return clients.account_id()
    except Exception:  # noqa: BLE001
        return "unknown"


def _not_found(err: Exception) -> bool:
    code = error_code(err)
    return code.endswith("NotFound") or code.endswith(".Malformed")


# ---------------------------------------------------------------- own describers (not actions.py's)


def _describe(clients: AwsClients, resource_type: str, rid: str) -> dict | None:
    ec2 = clients.ec2
    try:
        if resource_type == "volume":
            found = ec2.describe_volumes(VolumeIds=[rid]).get("Volumes") or []
        elif resource_type == "snapshot":
            found = ec2.describe_snapshots(SnapshotIds=[rid]).get("Snapshots") or []
        elif resource_type == "address":
            found = ec2.describe_addresses(AllocationIds=[rid]).get("Addresses") or []
        elif resource_type == "instance":
            found = [
                inst
                for res in ec2.describe_instances(InstanceIds=[rid]).get("Reservations") or []
                for inst in res.get("Instances") or []
                if inst.get("InstanceId") == rid and (inst.get("State") or {}).get("Name") != "terminated"
            ]
        else:
            return None
    except Exception as err:  # noqa: BLE001
        if _not_found(err):
            return None
        raise
    return found[0] if found else None


def _ami_users(clients: AwsClients, snapshot_id: str, cache: dict) -> list[str]:
    """Self-owned AMIs whose block devices use this snapshot (raises if AMIs cannot be listed)."""
    if "images" not in cache:
        images: list[dict] = []
        ec2 = clients.ec2
        if ec2.can_paginate("describe_images"):
            for page in ec2.get_paginator("describe_images").paginate(Owners=["self"]):
                images.extend(page.get("Images") or [])
        else:
            images = list(ec2.describe_images(Owners=["self"]).get("Images") or [])
        cache["images"] = images
    return [
        str(img.get("ImageId"))
        for img in cache["images"]
        if any((b.get("Ebs") or {}).get("SnapshotId") == snapshot_id for b in img.get("BlockDeviceMappings") or [])
    ]


def _dns_refs(clients: AwsClients, ip: str | None, cache: dict) -> list[str]:
    if not ip:
        return []
    if "dns" not in cache:
        from . import scanner

        # strict=True: a Route 53 outage must block (fail closed), not read as "no DNS records".
        # Built once per verify call: one Route 53 enumeration however many addresses are checked.
        cache["dns"] = dict(scanner.dns_index(clients, strict=True))
    return list(cache["dns"].get(str(ip).strip(), []))


def _associated(addr: dict) -> bool:
    return bool(addr.get("AssociationId") or addr.get("InstanceId") or addr.get("NetworkInterfaceId"))


def _action_check(
    clients: AwsClients, settings: Settings, action: str, rid: str, res: dict, now: float, cache: dict
) -> tuple[str | None, list[str]]:
    """(block reason or None, human-readable check lines) for the action-specific safety checks."""
    if action == "quarantine_volume":
        if res.get("State") != "available" or res.get("Attachments"):
            return f"volume is {res.get('State')} / attached now", []
        return None, [f"{rid}: still unattached (available)"]

    if action in ("recycle_snapshot", "delete_snapshot"):
        if res.get("State") != "completed":
            return f"snapshot is {res.get('State')}, not completed", []
        try:
            amis = _ami_users(clients, rid, cache)
        except Exception as err:  # noqa: BLE001 - fail closed
            return f"could not check which AMIs use it ({error_code(err)})", []
        if amis:
            return f"used by AMI {', '.join(amis)} - launches from it would break", []
        return None, [f"{rid}: completed and not used by any self-owned AMI"]

    if action == "stop_instance":
        state = (res.get("State") or {}).get("Name")
        if state != "running":
            return f"instance is {state}, not running", []
        if "lb_targets" not in cache:
            from . import scanner

            try:
                cache["lb_targets"] = dict(scanner.lb_target_instances(clients, strict=True))
            except Exception as err:  # noqa: BLE001 - fail closed
                return f"could not check load balancer target groups ({error_code(err)})", []
        groups = cache["lb_targets"].get(rid) or []
        if groups:
            return f"serving traffic via load balancer target group {', '.join(groups)}", []
        return None, [f"{rid}: still running and not registered in any load balancer target group"]

    if action in ("quarantine_address", "release_address"):
        ip = res.get("PublicIp")
        lines: list[str] = []
        if action == "release_address":
            until_raw = policy.tags_to_dict(res.get("Tags")).get(TAG_QUARANTINED_UNTIL)
            if not until_raw:
                return "must be quarantined first (quarantine_address), then released after the window", []
            until = _parse_epoch(until_raw)
            if until is None:
                return f"{TAG_QUARANTINED_UNTIL} tag is not a valid time ({until_raw!r})", []
            if until > now:
                return f"still in quarantine until {until_raw} ({countdown(until - now)} left)", []
            lines.append(f"{rid}: quarantine window ended at {until_raw}")
        if _associated(res):
            if action == "release_address":
                audit_mod.record_quarantine_void(
                    settings, rid, policy.tags_to_dict(res.get("Tags")), "seen associated by the watchdog"
                )
            return f"address {ip} is associated with something now", []
        if action == "release_address":
            problem = audit_mod.quarantine_problem(
                settings, rid, policy.tags_to_dict(res.get("Tags")), now=datetime.fromtimestamp(now, timezone.utc)
            )
            if problem:
                return f"{problem}; quarantine it again (quarantine_address) before any release", []
            lines.append(f"{rid}: Warden's own quarantine (receipt matches) and not seen in use since")
        try:
            refs = _dns_refs(clients, ip, cache)
        except Exception as err:  # noqa: BLE001 - fail closed
            return f"could not check DNS records ({error_code(err)})", []
        if refs:
            return (
                f"DNS record {'; '.join(refs)} points at {ip} - releasing would leave a dangling record "
                "(subdomain takeover risk)"
            ), []
        return None, lines + [f"{rid}: {ip} still unassociated and no DNS record points at it"]

    return f"watchdog has no checks for action {action!r}", []


def _check_item(
    clients: AwsClients, settings: Settings, item: plan_mod.PlanItem, action: str, now: float, cache: dict
) -> tuple[str | None, list[str]]:
    rid = item.resource_id
    res = _describe(clients, item.resource_type, rid)
    if res is None:
        return "no longer exists", []
    tags = policy.tags_to_dict(res.get("Tags"))
    if not policy.in_scope(tags, settings):
        return f"no longer in scope ({settings.scope_label})", []
    reasons = policy.keep_reasons(tags)
    if reasons:
        return "changed since the scan: " + "; ".join(reasons), []
    if plan_mod.fingerprint(item.resource_type, res) != item.fingerprint:
        return "changed since the scan (state or tags differ from the plan); re-scan and re-approve", []
    blocked, extra = _action_check(clients, settings, action, rid, res, now, cache)
    if blocked:
        return blocked, []
    lines = [
        f"{rid}: re-described independently; in scope ({settings.scope_label}), no protection/managed-by tags",
        f"{rid}: unchanged since the scan (fingerprint matches the plan)",
    ]
    return None, lines + extra


# ---------------------------------------------------------------- verify / sign-off


def verify(
    clients: AwsClients,
    settings: Settings,
    plan_id: str,
    action: str,
    resource_ids: list[str],
    now: float | None = None,
) -> dict:
    """Independently re-check a request and, if anything passes, issue a single-use sign-off token."""
    current = _now(now)
    signoff_id = _new_signoff_id()
    expires = current + settings.signoff_ttl_minutes * 60
    out: dict[str, Any] = {
        "signoff_id": signoff_id,
        "token": None,
        "expires_at": _iso(expires),
        "plan_id": plan_id,
        "action": action,
        "approved_ids": [],
        "blocked": {},
        "checks": [],
    }

    def finish() -> dict:
        if out["approved_ids"]:
            audit_mod.audit(
                settings, "watchdog_signoff", signoff_id=signoff_id, plan_id=plan_id, action=action,
                approved_ids=out["approved_ids"], blocked=out["blocked"], expires_at=out["expires_at"],
            )
        else:
            audit_mod.audit(
                settings, "watchdog_block", signoff_id=signoff_id, plan_id=plan_id, action=action,
                resource_ids=_requested(resource_ids), blocked=out["blocked"],
            )
        return out

    if is_frozen(settings):
        out["blocked"] = {rid: FROZEN_REASON for rid in _requested(resource_ids)}
        out["checks"].append("freeze is on: nothing may change")
        return finish()

    ids = list(resource_ids) if isinstance(resource_ids, (list, tuple)) else resource_ids
    plan, approved, rejected = plan_mod.validate_request(
        plan_id, action, ids, settings, _account(clients), settings.region, now=current
    )
    if "*" in rejected:
        out["blocked"] = {rid: rejected["*"] for rid in _requested(resource_ids)}
        return finish()
    out["blocked"].update(rejected)
    out["checks"].append(f"plan {plan_id} is valid and certifies {action} for {len(approved)} requested id(s)")

    cache: dict = {}
    fingerprints: dict[str, str] = {}
    for rid in approved:
        item = plan.items[rid]
        try:
            reason, lines = _check_item(clients, settings, item, action, current, cache)
        except Exception as err:  # noqa: BLE001 - fail closed
            reason, lines = f"could not verify ({error_code(err)})", []
        if reason:
            out["blocked"][rid] = reason
            out["checks"].append(f"{rid}: BLOCKED - {reason}")
        else:
            out["approved_ids"].append(rid)
            fingerprints[rid] = item.fingerprint
            out["checks"].extend(lines)

    if out["approved_ids"]:
        record = {
            "signoff_id": signoff_id,
            "plan_id": plan_id,
            "action": action,
            "approved_ids": list(out["approved_ids"]),
            "fingerprints": fingerprints,
            "expires_at_epoch": expires,
            "created_at": _iso(current),
        }
        key = _load_key(settings, create=True)
        if key is None:
            out["blocked"].update({rid: "watchdog key unavailable" for rid in out["approved_ids"]})
            out["approved_ids"] = []
            return finish()
        audit_mod.write_json_atomic(_signoffs_dir(settings) / f"{signoff_id}.json", record)
        out["token"] = f"{signoff_id}.{_mac(key, record)}"
        out["checks"].append(
            f"sign-off {signoff_id} valid for one executor call until {out['expires_at']}"
        )
    return finish()


def check_signoff(
    settings: Settings,
    token: str,
    plan_id: str,
    action: str,
    resource_ids: list[str],
    now: float | None = None,
) -> tuple[bool, str, dict]:
    """Validate and consume a sign-off token. Returns (ok, reason, fingerprints of the requested ids)."""
    current = _now(now)

    def reject(reason: str, sid: str | None = None) -> tuple[bool, str, dict]:
        audit_mod.audit(
            settings, "watchdog_signoff_rejected", signoff_id=sid, plan_id=plan_id, action=action,
            resource_ids=_requested(resource_ids), reason=reason,
        )
        return False, reason, {}

    if not isinstance(token, str) or token.count(".") != 1:
        return reject("malformed sign-off token")
    sid, mac = token.strip().split(".")
    if not _SIGNOFF_ID.match(sid) or not _MAC.match(mac):
        return reject("malformed sign-off token")
    path = _signoffs_dir(settings) / f"{sid}.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return reject("unknown sign-off id", sid)
    except (OSError, ValueError):
        return reject("invalid sign-off record", sid)
    if not isinstance(record, dict) or record.get("signoff_id") != sid:
        return reject("invalid sign-off record", sid)
    key = _load_key(settings, create=False)
    if key is None or not hmac.compare_digest(_mac(key, record), mac):
        return reject("signature mismatch (token forged or record altered)", sid)
    try:
        expires = float(record.get("expires_at_epoch"))
    except (TypeError, ValueError):
        return reject("invalid sign-off record", sid)
    if current >= expires:
        return reject(f"sign-off expired at {_iso(expires)}", sid)
    if record.get("plan_id") != plan_id:
        return reject(f"sign-off is for plan {record.get('plan_id')}, not {plan_id}", sid)
    if record.get("action") != action:
        return reject(f"sign-off is for {record.get('action')}, not {action}", sid)
    ids = _requested(resource_ids)
    approved = record.get("approved_ids") or []
    missing = [rid for rid in ids if rid not in approved]
    if missing:
        return reject(f"{', '.join(missing)} not approved by the watchdog", sid)
    consumed = _signoffs_dir(settings) / f"{sid}.consumed"
    try:
        fd = os.open(consumed, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return reject("sign-off already used (single use)", sid)
    except OSError as err:
        return reject(f"could not record sign-off use ({type(err).__name__})", sid)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(_iso(current))
    audit_mod.audit(
        settings, "watchdog_signoff_consumed", signoff_id=sid, plan_id=plan_id, action=action, resource_ids=ids
    )
    fingerprints = record.get("fingerprints") or {}
    return True, "ok", {rid: fingerprints.get(rid) for rid in ids}


# ---------------------------------------------------------------- rollback window


def _window_item(
    resource_id: str,
    resource_type: str,
    state: str,
    since: str | None,
    until: float | None,
    now: float,
    undo: dict | None,
    finalize: str | None = None,
    flags: list[str] | None = None,
    **extra: Any,
) -> dict:
    """until=None means no deadline (seconds_remaining 0, countdown 'no deadline')."""
    if until is None:
        remaining, text = 0, "no deadline"
    else:
        remaining = max(0, int(until - now))
        text = countdown(until - now)
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "state": state,
        "since": since,
        "until": _iso(until) if until is not None else None,
        "seconds_remaining": remaining,
        "countdown": text,
        "undo": undo,
        "finalize": finalize,
        "flags": list(flags or []),
        **extra,
    }


def _restored(settings: Settings) -> dict[str, str]:
    """backup snapshot id -> volume Warden restored from it (from restore_volume receipts)."""
    out: dict[str, str] = {}
    for summary in audit_mod.list_receipts(settings, limit=100_000):
        if summary.get("action") != "restore_volume":
            continue
        receipt = audit_mod.load_receipt(settings, str(summary.get("receipt_id"))) or {}
        for r in receipt.get("results") or []:
            if r.get("status") == "done" and r.get("resource_id"):
                out[str(r["resource_id"])] = str(r.get("restored_volume_id") or "a new volume")
    return out


def _backups(clients: AwsClients, settings: Settings, now: float) -> list[dict]:
    restored = _restored(settings)
    snaps = clients.ec2.describe_snapshots(
        OwnerIds=["self"], Filters=[{"Name": "tag-key", "Values": [TAG_BACKUP_OF]}]
    ).get("Snapshots") or []
    items = []
    for snap in snaps:
        tags = policy.tags_to_dict(snap.get("Tags"))
        if TAG_BACKUP_OF not in tags or not policy.in_scope(tags, settings):
            continue
        sid = snap["SnapshotId"]
        until = _parse_epoch(tags.get(TAG_EXPIRES_AT))
        flags = []
        if until is None:
            flags.append(f"backup has no valid {TAG_EXPIRES_AT} tag")
        elif until <= now:
            flags.append("backup is past its expiry - a later scan may offer to remove it")
        if snap.get("State") != "completed":
            flags.append(f"backup snapshot is {snap.get('State')}, not completed yet")
        started = _parse_epoch(snap.get("StartTime"))
        undo: dict | None = {"tool": "restore_volume", "args": {"backup_snapshot_id": sid}}
        if sid in restored:
            undo = None  # restoring again would create a duplicate volume
            flags.append(f"already restored as {restored[sid]} - nothing to undo")
        items.append(_window_item(
            tags[TAG_BACKUP_OF], "volume", "backup", _iso(started) if started is not None else None, until, now,
            undo, flags=flags, backup_snapshot_id=sid,
        ))
    return items


def _recycled(clients: AwsClients, settings: Settings, now: float) -> list[dict]:
    latest: dict[str, str] = {}
    for summary in audit_mod.list_receipts(settings, limit=100_000):
        if summary.get("action") != "recycle_snapshot":
            continue
        receipt = audit_mod.load_receipt(settings, str(summary.get("receipt_id"))) or {}
        when = str(receipt.get("finished_at") or receipt.get("started_at") or "")
        for r in receipt.get("results") or []:
            if r.get("status") == "done" and r.get("resource_id"):
                rid = str(r["resource_id"])
                if rid not in latest or when > latest[rid]:
                    latest[rid] = when
    if not latest:
        return []
    ids = sorted(latest)
    exit_times: dict[str, Any] | None
    note = None
    try:
        resp = clients.ec2.list_snapshots_in_recycle_bin(SnapshotIds=ids)
        exit_times = {s.get("SnapshotId"): s.get("RecycleBinExitTime") for s in resp.get("Snapshots") or []}
    except Exception as err:  # noqa: BLE001
        exit_times, note = None, f"Recycle Bin API unavailable ({error_code(err)}); end time estimated"
    items = []
    for rid in ids:
        since = latest[rid] or None
        since_epoch = _parse_epoch(since)
        flags = [note] if note else []
        undo = {"tool": "restore_snapshot", "args": {"snapshot_id": rid}}
        if exit_times is not None and rid not in exit_times:
            try:
                live = _describe(clients, "snapshot", rid)
            except Exception:  # noqa: BLE001
                live = None
            if live is not None:
                continue  # restored: no longer in the rollback window
            flags.append("no longer in the Recycle Bin - retention ended; not recoverable")
            items.append(_window_item(rid, "snapshot", "recycled", since, now, now, None, flags=flags))
            continue
        until = _parse_epoch((exit_times or {}).get(rid))
        if until is None:
            base = since_epoch if since_epoch is not None else now
            until = base + RECYCLE_FALLBACK_DAYS * 86400
        items.append(_window_item(rid, "snapshot", "recycled", since, until, now, undo, flags=flags))
    return items


def _stopped(clients: AwsClients, settings: Settings, now: float) -> list[dict]:
    resp = clients.ec2.describe_instances(Filters=[{"Name": "tag-key", "Values": [TAG_STOPPED_AT]}])
    items = []
    for res in resp.get("Reservations") or []:
        for inst in res.get("Instances") or []:
            tags = policy.tags_to_dict(inst.get("Tags"))
            state = (inst.get("State") or {}).get("Name")
            if TAG_STOPPED_AT not in tags or state == "terminated" or not policy.in_scope(tags, settings):
                continue
            iid = inst["InstanceId"]
            flags: list[str] = []
            undo = None
            if state == "stopped":
                undo = {"tool": "start_instances", "args": {"instance_ids": [iid]}}
            elif state in ("running", "pending"):
                flags.append("restarted outside Warden - Warden will not touch it again without a new scan")
            else:
                flags.append(f"instance is {state}; undo available once it is stopped")
            items.append(_window_item(iid, "instance", "stopped", tags[TAG_STOPPED_AT], None, now, undo, flags=flags))
    return items


def _quarantined(clients: AwsClients, settings: Settings, now: float) -> list[dict]:
    addrs = clients.ec2.describe_addresses().get("Addresses") or []
    items = []
    for addr in addrs:
        tags = policy.tags_to_dict(addr.get("Tags"))
        if TAG_QUARANTINED_UNTIL not in tags or not addr.get("AllocationId") or not policy.in_scope(tags, settings):
            continue
        alloc = addr["AllocationId"]
        until = _parse_epoch(tags[TAG_QUARANTINED_UNTIL])
        flags = []
        if until is None:
            flags.append(f"{TAG_QUARANTINED_UNTIL} is not a valid time")
        if _associated(addr):
            audit_mod.record_quarantine_void(settings, alloc, tags, "seen associated by rollback_window")
            flags.append("in use again - quarantine void: Warden will not release it; a new scan offers a fresh "
                         "quarantine once it is unused again")
        items.append(_window_item(
            alloc, "address", "quarantined", tags.get(TAG_QUARANTINED_AT), until, now,
            {"tool": "cancel_address_quarantine", "args": {"allocation_id": alloc}},
            finalize="release_address after the window (irreversible, needs its own approval)",
            flags=flags, public_ip=addr.get("PublicIp"),
        ))
    return items


def rollback_window(clients: AwsClients, settings: Settings, now: float | None = None) -> dict:
    """Everything Warden changed that can still be undone, with a live countdown per item."""
    current = _now(now)
    items: list[dict] = []
    notes: list[str] = []
    sources = (
        ("Warden backups", _backups),
        ("recycled snapshots", _recycled),
        ("stopped instances", _stopped),
        ("quarantined Elastic IPs", _quarantined),
    )
    for label, source in sources:
        try:
            items.extend(source(clients, settings, current))
        except Exception as err:  # noqa: BLE001 - one unavailable API must not hide the rest
            notes.append(f"{label} unavailable ({error_code(err)}); not listed")
    items.sort(key=lambda i: (i["until"] is None, i["seconds_remaining"], i["resource_id"]))
    return {
        "generated_at": _iso(current),
        "items": items,
        "notes": notes,
        "ledger": audit_mod.verify_ledger(settings),
    }
