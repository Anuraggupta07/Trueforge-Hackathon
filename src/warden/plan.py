"""Plan lock: the scanner certifies ids; actions may only touch certified ids."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .audit import new_id, write_json_atomic
from .config import Settings


@dataclass(frozen=True)
class ActionSpec:
    name: str
    resource_type: str
    reversible: bool


ACTIONS: dict[str, ActionSpec] = {
    spec.name: spec
    for spec in (
        ActionSpec("quarantine_volume", "volume", True),
        ActionSpec("recycle_snapshot", "snapshot", True),
        ActionSpec("delete_snapshot", "snapshot", False),
        ActionSpec("stop_instance", "instance", True),
        ActionSpec("quarantine_address", "address", True),
        ActionSpec("release_address", "address", False),
    )
}

VERDICTS = ("act", "keep", "review")
WILDCARDS = {"*", "all", ""}
_PLAN_ID = re.compile(r"^plan-[A-Za-z0-9-]+$")


@dataclass
class PlanItem:
    resource_id: str
    resource_type: str
    verdict: str  # "act" | "keep" | "review"
    action: str | None
    fingerprint: str


@dataclass
class Plan:
    plan_id: str
    created_at: float
    expires_at: float
    account_id: str
    region: str
    items: dict[str, PlanItem] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["items"] = {rid: asdict(item) for rid, item in self.items.items()}
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Plan":
        items = {rid: PlanItem(**item) for rid, item in (data.get("items") or {}).items()}
        return cls(
            plan_id=data["plan_id"],
            created_at=float(data["created_at"]),
            expires_at=float(data["expires_at"]),
            account_id=str(data["account_id"]),
            region=str(data["region"]),
            items=items,
        )


def _sorted_tags(resource: dict) -> list[list[str]]:
    return sorted([str(t.get("Key")), str(t.get("Value") or "")] for t in resource.get("Tags") or [])


def fingerprint(resource_type: str, resource: dict) -> str:
    """sha256 of the state-relevant fields of a described resource."""
    if resource_type == "volume":
        fields: dict[str, Any] = {
            "State": resource.get("State"),
            "InstanceIds": sorted(
                str(a.get("InstanceId")) for a in resource.get("Attachments") or [] if a.get("InstanceId")
            ),
            "Size": resource.get("Size"),
            "VolumeType": resource.get("VolumeType"),
        }
    elif resource_type == "snapshot":
        fields = {"State": resource.get("State"), "VolumeId": resource.get("VolumeId")}
    elif resource_type == "instance":
        fields = {
            "State": (resource.get("State") or {}).get("Name"),
            "InstanceType": resource.get("InstanceType"),
        }
    elif resource_type == "address":
        fields = {k: resource.get(k) for k in ("AssociationId", "InstanceId", "NetworkInterfaceId", "PublicIp")}
    else:
        raise ValueError(f"unknown resource_type {resource_type!r}")
    fields["Tags"] = _sorted_tags(resource)
    canonical = json.dumps({"type": resource_type, **fields}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def new_plan(
    account_id: str, region: str, items: list[PlanItem], settings: Settings, now: float | None = None
) -> Plan:
    """Create a plan that expires after settings.plan_ttl_minutes."""
    created = time.time() if now is None else now
    return Plan(
        plan_id=new_id("plan"),
        created_at=created,
        expires_at=created + settings.plan_ttl_minutes * 60,
        account_id=account_id,
        region=region,
        items={item.resource_id: item for item in items},
    )


def _plan_path(plan_id: str, settings: Settings) -> Path:
    return settings.state_dir / "plans" / f"{plan_id}.json"


def save_plan(plan: Plan, settings: Settings) -> Path:
    """Atomically write the plan to state_dir/plans/<plan_id>.json."""
    if not _PLAN_ID.match(plan.plan_id):
        raise ValueError(f"invalid plan_id {plan.plan_id!r}")
    return write_json_atomic(_plan_path(plan.plan_id, settings), plan.to_dict())


def load_plan(plan_id: str, settings: Settings) -> Plan | None:
    """Load a plan, or None when missing, malformed or the id is unsafe."""
    if not isinstance(plan_id, str) or not _PLAN_ID.match(plan_id):
        return None
    try:
        return Plan.from_dict(json.loads(_plan_path(plan_id, settings).read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _fail(reason: str, plan: Plan | None = None) -> tuple[Plan | None, list[str], dict[str, str]]:
    return plan, [], {"*": reason}


def validate_request(
    plan_id: str,
    action: str,
    resource_ids: list[str],
    settings: Settings,
    account_id: str,
    region: str,
    now: float | None = None,
) -> tuple[Plan | None, list[str], dict[str, str]]:
    """Check a mutating request against its plan. Returns (plan, approved_ids, rejected)."""
    spec = ACTIONS.get(action)
    if spec is None:
        return _fail(f"unknown action {action!r}")
    plan = load_plan(plan_id, settings)
    if plan is None:
        return _fail(f"plan {plan_id!r} not found; run scan_for_waste first")
    current = time.time() if now is None else now
    if current >= plan.expires_at:
        return _fail(f"plan {plan_id} has expired; run scan_for_waste again", plan)
    if plan.account_id != account_id or plan.region != region:
        return _fail(
            f"plan {plan_id} was made for account {plan.account_id} in {plan.region}, "
            f"not {account_id} in {region}",
            plan,
        )
    if not isinstance(resource_ids, list) or not resource_ids:
        return _fail("resource ids must be a non-empty list", plan)
    ids: list[str] = []
    for rid in resource_ids:
        if not isinstance(rid, str) or not rid.strip():
            return _fail("every resource id must be a non-empty string", plan)
        rid = rid.strip()
        if rid.lower() in WILDCARDS or "*" in rid:
            return _fail(f"wildcard id {rid!r} is not allowed; list explicit ids", plan)
        if rid not in ids:
            ids.append(rid)
    if not spec.reversible and len(ids) != 1:
        return _fail(f"{action} is irreversible: exactly one id per call (got {len(ids)})", plan)
    if spec.reversible and len(ids) > settings.max_batch:
        return _fail(f"batch of {len(ids)} exceeds the limit of {settings.max_batch}", plan)

    approved: list[str] = []
    rejected: dict[str, str] = {}
    for rid in ids:
        item = plan.items.get(rid)
        if item is None:
            rejected[rid] = f"not in plan {plan_id}"
        elif item.resource_type != spec.resource_type:
            rejected[rid] = f"is a {item.resource_type}, but {action} applies to {spec.resource_type}s"
        elif item.verdict != "act":
            rejected[rid] = f"plan verdict is {item.verdict!r}, not 'act'"
        elif item.action != action:
            rejected[rid] = f"plan action is {item.action!r}, not {action!r}"
        else:
            approved.append(rid)
    return plan, approved, rejected
