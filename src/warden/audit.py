"""Audit log, ids and receipt storage under settings.state_dir."""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings

_PREFIXES = {"plan", "rcpt"}
_RECEIPT_ID = re.compile(r"^rcpt-[A-Za-z0-9-]+$")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """Current UTC time as ISO-8601 with a Z suffix."""
    return _utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id(prefix: str) -> str:
    """New id like 'plan-20260926T120301-3fa2c1'."""
    if prefix not in _PREFIXES:
        raise ValueError(f"unknown id prefix {prefix!r}")
    return f"{prefix}-{_utcnow().strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"


def write_json_atomic(path: Path, data: Any) -> Path:
    """Write JSON to path via a temp file + rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)
    return path


def audit(settings: Settings, event: str, **fields: Any) -> None:
    """Append one JSON line to state_dir/audit.jsonl."""
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": iso_now(), "event": event, **fields}, default=str)
    with open(settings.state_dir / "audit.jsonl", "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _receipts_dir(settings: Settings) -> Path:
    return settings.state_dir / "receipts"


def save_receipt(settings: Settings, receipt: dict) -> Path:
    """Persist a receipt to state_dir/receipts/<receipt_id>.json."""
    receipt_id = str(receipt.get("receipt_id", ""))
    if not _RECEIPT_ID.match(receipt_id):
        raise ValueError(f"invalid receipt_id {receipt_id!r}")
    return write_json_atomic(_receipts_dir(settings) / f"{receipt_id}.json", receipt)


def load_receipt(settings: Settings, receipt_id: str) -> dict | None:
    """Load a receipt by id, or None if missing/invalid."""
    if not isinstance(receipt_id, str) or not _RECEIPT_ID.match(receipt_id):
        return None
    path = _receipts_dir(settings) / f"{receipt_id}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_receipts(settings: Settings, limit: int = 20) -> list[dict]:
    """Newest-first receipt summaries."""
    folder = _receipts_dir(settings)
    if not folder.is_dir():
        return []
    summaries: list[dict] = []
    for path in folder.glob("rcpt-*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        summaries.append(
            {
                "receipt_id": data.get("receipt_id"),
                "action": data.get("action"),
                "plan_id": data.get("plan_id"),
                "finished_at": data.get("finished_at"),
                "counts": data.get("counts"),
            }
        )
    summaries.sort(key=lambda s: (str(s.get("finished_at") or ""), str(s.get("receipt_id"))), reverse=True)
    return summaries[: max(0, int(limit))]
