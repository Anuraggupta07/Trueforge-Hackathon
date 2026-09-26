"""Mock mode: run Warden against a local moto server instead of real AWS.

Enabled by WARDEN_MOCK_ENDPOINT (e.g. http://127.0.0.1:5000, started with scripts/mock_server.py).
Every client then uses dummy credentials and that endpoint, so real AWS is never reached.

moto lacks a few things Warden relies on; this module fills them with botocore event hooks
(so paginators and waiters are covered too):

- Recycle Bin: the rbin API and EC2's list/restore_snapshot(s)_from/in_recycle_bin are simulated.
  A delete_snapshot covered by a rule moves the snapshot into the simulated bin (hidden from
  describe_snapshots, restorable with the same id) instead of deleting it. State lives in
  <state_dir>/mock/recycle_bin.json so the MCP server and the demo scripts share it.
- Instance age: moto launches instances "now", which Warden's boot warm-up treats as too new
  to judge. describe_instances reports LaunchTime MOCK_INSTANCE_AGE earlier.
- CloudWatch: moto has no EC2 metrics; seed_idle_metrics() writes a synthetic idle history.
- CloudTrail lookup_events is not implemented by moto; it returns no events.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import Settings

MOCK_CREDENTIALS = {"aws_access_key_id": "testing", "aws_secret_access_key": "testing"}
MOCK_ACCOUNT_ID = "123456789012"  # moto's default account
MOCK_INSTANCE_AGE = timedelta(hours=2)
STATE_FILE = Path("mock") / "recycle_bin.json"

_PARAMS = "warden_mock_params"
_lock = threading.RLock()
_local = threading.local()  # _local.purging: let a real moto delete through


class _Http:
    """Minimal stand-in for a botocore HTTP response (botocore only reads these fields)."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self.raw = None
        self.content = b""
        self.text = ""


def _ok(body: dict) -> tuple[_Http, dict]:
    return _Http(200), {**body, "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": str(uuid.uuid4())}}


def _error(code: str, message: str, status: int = 400) -> tuple[_Http, dict]:
    return _Http(status), {
        "Error": {"Code": code, "Message": message},
        "ResponseMetadata": {"HTTPStatusCode": status, "RequestId": str(uuid.uuid4())},
    }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(text: str) -> datetime:
    return datetime.fromisoformat(text)


# --------------------------------------------------------------------------- shared state


def state_path(settings: Settings) -> Path:
    return settings.state_dir / STATE_FILE


def reset_state(settings: Settings) -> None:
    """Forget the simulated Recycle Bin (call when a fresh moto server starts)."""
    path = state_path(settings)
    if path.exists():
        path.unlink()


def _load(settings: Settings) -> dict:
    try:
        data = json.loads(state_path(settings).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    data.setdefault("rules", {})
    data.setdefault("bin", {})
    return data


def _save(settings: Settings, data: dict) -> None:
    path = state_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def _capture_params(params: dict, context: dict, **_: Any) -> None:
    """before-parameter-build: keep the caller's API arguments (before-call only sees the serialized request)."""
    context[_PARAMS] = dict(params)


def _params(context: dict | None) -> dict:
    return (context or {}).get(_PARAMS) or {}


def _retention(rule: dict) -> timedelta:
    period = rule.get("RetentionPeriod") or {}
    return timedelta(days=int(period.get("RetentionPeriodValue") or 0))


# --------------------------------------------------------------------------- Recycle Bin (rbin API)


def _rbin_handler(settings: Settings):
    def handler(model: Any, context: dict, **_: Any) -> tuple[_Http, dict] | None:
        op, params = model.name, _params(context)
        with _lock:
            data = _load(settings)
            rules: dict[str, dict] = data["rules"]
            if op == "CreateRule":
                rule_id = uuid.uuid4().hex[:11]
                rule = {
                    "Identifier": rule_id,
                    "RuleArn": f"arn:aws:rbin:{settings.region}:{MOCK_ACCOUNT_ID}:rule/{rule_id}",
                    "ResourceType": params.get("ResourceType"),
                    "RetentionPeriod": params.get("RetentionPeriod"),
                    "ResourceTags": params.get("ResourceTags") or [],
                    "ExcludeResourceTags": params.get("ExcludeResourceTags") or [],
                    "Description": params.get("Description", ""),
                    "Status": "available",
                    "LockState": "unlocked",
                    "Tags": params.get("Tags") or [],
                }
                rules[rule_id] = rule
                _save(settings, data)
                return _ok({k: v for k, v in rule.items() if k != "Tags"})
            if op == "ListRules":
                wanted = params.get("ResourceType")
                summaries = [
                    {k: r[k] for k in ("Identifier", "Description", "RetentionPeriod", "LockState", "RuleArn")}
                    for r in rules.values() if not wanted or r["ResourceType"] == wanted
                ]
                return _ok({"Rules": summaries})
            rule = rules.get(params.get("Identifier", ""))
            if op == "ListTagsForResource":
                arn = params.get("ResourceArn")
                match = next((r for r in rules.values() if r["RuleArn"] == arn), None)
                if match is None:
                    return _error("ResourceNotFoundException", f"no rule {arn}")
                return _ok({"Tags": match.get("Tags") or []})
            if rule is None:
                return _error("ResourceNotFoundException", f"no rule {params.get('Identifier')}")
            if op == "GetRule":
                return _ok({k: v for k, v in rule.items() if k != "Tags"})
            if op == "DeleteRule":
                del rules[rule["Identifier"]]
                _save(settings, data)
                return _ok({})
        return _error("NotImplemented", f"rbin {op} is not simulated in Warden mock mode")

    return handler


# --------------------------------------------------------------------------- Recycle Bin (EC2 side)


def _keeps(rule: dict, tags: dict[str, str]) -> bool:
    """Would this rule keep a snapshot with exactly these tags (what AWS checks at delete time)?"""
    from .scanner import _tag_matches

    if rule.get("ResourceType") != "EBS_SNAPSHOT" or rule.get("Status") != "available":
        return False
    included = rule.get("ResourceTags") or []
    if included:
        return any(_tag_matches(t, tags) for t in included)
    return not any(_tag_matches(t, tags) for t in rule.get("ExcludeResourceTags") or [])


def _covering_rule(rules: dict[str, dict], tags: dict[str, str]) -> dict | None:
    return next((r for r in rules.values() if _keeps(r, tags)), None)


def _purge_expired(ec2: Any, data: dict) -> bool:
    """Really delete (in moto) binned snapshots whose retention ran out. True if anything changed."""
    changed = False
    for snap_id, entry in list(data["bin"].items()):
        if _parse(entry["RecycleBinExitTime"]) <= _now():
            _local.purging = True
            try:
                ec2.delete_snapshot(SnapshotId=snap_id)
            except Exception:  # noqa: BLE001 - already gone
                pass
            finally:
                _local.purging = False
            del data["bin"][snap_id]
            changed = True
    return changed


def _install_ec2_hooks(client: Any, settings: Settings) -> None:
    from .policy import tags_to_dict

    events = client.meta.events

    def delete_snapshot(context: dict, **_: Any) -> tuple[_Http, dict] | None:
        params = _params(context)
        if params.get("DryRun") or getattr(_local, "purging", False):
            return None
        snap_id = params.get("SnapshotId", "")
        with _lock:
            data = _load(settings)
            if snap_id in data["bin"]:
                return _error("InvalidSnapshot.NotFound", f"The snapshot '{snap_id}' does not exist.")
            snaps = client.describe_snapshots(SnapshotIds=[snap_id]).get("Snapshots") or []
            if not snaps:
                return None  # let moto answer (NotFound)
            snap = snaps[0]
            rule = _covering_rule(data["rules"], tags_to_dict(snap.get("Tags")))
            if rule is None:
                return None  # no rule keeps it: moto deletes it for real
            entered = _now()
            data["bin"][snap_id] = {
                "SnapshotId": snap_id,
                "Description": snap.get("Description", ""),
                "VolumeId": snap.get("VolumeId", ""),
                "VolumeSize": snap.get("VolumeSize"),
                "RecycleBinEnterTime": entered.isoformat(),
                "RecycleBinExitTime": (entered + _retention(rule)).isoformat(),
            }
            _save(settings, data)
        return _ok({})

    def hide_binned(parsed: dict, **_: Any) -> None:
        snaps = parsed.get("Snapshots")
        if not snaps:
            return
        binned = _load(settings)["bin"]
        if binned:
            parsed["Snapshots"] = [s for s in snaps if s.get("SnapshotId") not in binned]

    def list_bin(context: dict, **_: Any) -> tuple[_Http, dict]:
        params = _params(context)
        wanted = set(params.get("SnapshotIds") or [])
        with _lock:
            data = _load(settings)
            if _purge_expired(client, data):
                _save(settings, data)
        rows = [
            {**{k: v for k, v in e.items() if k != "VolumeSize"},
             "RecycleBinEnterTime": _parse(e["RecycleBinEnterTime"]),
             "RecycleBinExitTime": _parse(e["RecycleBinExitTime"])}
            for sid, e in data["bin"].items() if not wanted or sid in wanted
        ]
        return _ok({"Snapshots": rows})

    def restore(context: dict, **_: Any) -> tuple[_Http, dict] | None:
        params = _params(context)
        if params.get("DryRun"):
            return _error("DryRunOperation", "Request would have succeeded, but DryRun flag is set.")
        snap_id = params.get("SnapshotId", "")
        with _lock:
            data = _load(settings)
            entry = data["bin"].pop(snap_id, None)
            if entry is None:
                return _error("InvalidSnapshot.NotFound", f"The snapshot '{snap_id}' is not in the Recycle Bin.")
            _save(settings, data)
        return _ok({"SnapshotId": snap_id, "Description": entry.get("Description", ""),
                    "VolumeId": entry.get("VolumeId", ""), "VolumeSize": entry.get("VolumeSize"),
                    "State": "completed"})

    def age_instances(parsed: dict, **_: Any) -> None:
        for reservation in parsed.get("Reservations") or []:
            for inst in reservation.get("Instances") or []:
                launched = inst.get("LaunchTime")
                if isinstance(launched, datetime):
                    inst["LaunchTime"] = launched - MOCK_INSTANCE_AGE

    events.register("before-call.ec2.DeleteSnapshot", delete_snapshot)
    events.register("after-call.ec2.DescribeSnapshots", hide_binned)
    events.register("before-call.ec2.ListSnapshotsInRecycleBin", list_bin)
    events.register("before-call.ec2.RestoreSnapshotFromRecycleBin", restore)
    events.register("after-call.ec2.DescribeInstances", age_instances)


def _install_cloudtrail_hooks(client: Any) -> None:
    client.meta.events.register("before-call.cloudtrail.LookupEvents", lambda **_: _ok({"Events": []}))


def install_hooks(service: str, client: Any, settings: Settings) -> Any:
    """Attach the mock-mode shims for this service (no-op for services moto covers fully)."""
    client.meta.events.register(f"before-parameter-build.{client.meta.service_model.service_id.hyphenize()}",
                                _capture_params)
    if service == "rbin":
        client.meta.events.register("before-call.rbin.*", _rbin_handler(settings))
    elif service == "ec2":
        _install_ec2_hooks(client, settings)
    elif service == "cloudtrail":
        _install_cloudtrail_hooks(client)
    return client


# --------------------------------------------------------------------------- synthetic CloudWatch


def seed_idle_metrics(cloudwatch: Any, instance_id: str, hours_back: int = 3, hours_ahead: int = 12,
                      cpu_pct: float = 0.8, net_bytes: float = 2_000.0) -> int:
    """Write a flat, idle CPU/network history for an instance every 5 minutes, from hours_back ago to
    hours_ahead from now (so any scan today finds datapoints in its lookback window). Returns the count."""
    start = _now().replace(second=0, microsecond=0) - timedelta(hours=hours_back)
    stamps = [start + timedelta(minutes=5 * i) for i in range((hours_back + hours_ahead) * 12)]
    dims = [{"Name": "InstanceId", "Value": instance_id}]
    for i in range(0, len(stamps), 20):
        batch = []
        for ts in stamps[i:i + 20]:
            batch += [
                {"MetricName": "CPUUtilization", "Dimensions": dims, "Timestamp": ts, "Value": cpu_pct,
                 "Unit": "Percent"},
                {"MetricName": "NetworkIn", "Dimensions": dims, "Timestamp": ts, "Value": net_bytes,
                 "Unit": "Bytes"},
                {"MetricName": "NetworkOut", "Dimensions": dims, "Timestamp": ts, "Value": net_bytes,
                 "Unit": "Bytes"},
            ]
        for j in range(0, len(batch), 1000):
            cloudwatch.put_metric_data(Namespace="AWS/EC2", MetricData=batch[j:j + 1000])
    return len(stamps)
