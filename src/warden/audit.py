"""Audit log (a hash-chained ledger), ids and receipt storage under settings.state_dir.

Every audit.jsonl line carries seq (1-based), prev_hash ("GENESIS" for the first chained entry) and
hash = sha256(prev_hash + canonical JSON of the entry without "hash"). Editing, deleting or reordering a
line breaks the chain, which verify_ledger() reports. The newest (seq, hash) is also kept in state_dir/ledger.head,
so a truncated tail or a deleted ledger is reported too. The next write does not launder such a break: it
appends a ledger_tamper_detected entry and keeps the old anchor in state_dir/ledger.broken, so verify_ledger
keeps failing. The chain is not signed: someone who can rewrite all these files consistently can still forge
history.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import TAG_QUARANTINED_AT, TAG_QUARANTINED_UNTIL, Settings

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


GENESIS = "GENESIS"
LEDGER_FILE = "audit.jsonl"
HEAD_FILE = "ledger.head"
BREAK_FILE = "ledger.broken"  # sticky record of a detected truncation/rewrite
_LEDGER_LOCK = threading.Lock()
_TAIL_CHUNK = 8192


def _ledger_path(settings: Settings) -> Path:
    return settings.state_dir / LEDGER_FILE


def _canonical(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(prev_hash: str, entry: dict) -> str:
    """sha256(prev_hash + canonical JSON of the entry without its "hash" field)."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


def _last_chained(path: Path) -> tuple[int, str]:
    """(seq, hash) of the last chained entry, read from the file's tail; (0, GENESIS) if none."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            pos, buf = end, b""
            while pos > 0:
                step = min(_TAIL_CHUNK, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                lines = buf.split(b"\n")
                # lines[0] may be a partial line unless we reached the start of the file.
                candidates = lines if pos == 0 else lines[1:]
                for raw in reversed(candidates):
                    if not raw.strip():
                        continue
                    try:
                        entry = json.loads(raw.decode("utf-8"))
                    except ValueError:
                        continue  # torn/corrupt line: verify_ledger reports it; keep looking
                    if not isinstance(entry, dict):
                        continue
                    if "hash" not in entry:
                        return 0, GENESIS  # legacy (unchained) tail: start a new chain
                    return int(entry.get("seq") or 0), str(entry["hash"])
                if pos > 0:
                    buf = lines[0]
    except OSError:
        pass
    return 0, GENESIS


def _head_behind(head: dict | None, seq: int, tail_hash: str) -> bool:
    """True when the ledger no longer reaches its head anchor (truncated, deleted or tail rewritten)."""
    if head is None:
        return False
    head_seq = head.get("seq")
    if not isinstance(head_seq, int):
        return True  # unreadable anchor: never overwrite it silently
    return head_seq > seq or (head_seq == seq and head.get("hash") != tail_hash)


def _read_break(settings: Settings) -> dict | None:
    try:
        data = json.loads((settings.state_dir / BREAK_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"reason": f"{BREAK_FILE} is unreadable"}
    return data if isinstance(data, dict) else {"reason": f"{BREAK_FILE} is unreadable"}


def audit(settings: Settings, event: str, **fields: Any) -> None:
    """Append one hash-chained JSON line to state_dir/audit.jsonl (thread-safe)."""
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    path = _ledger_path(settings)
    with _LEDGER_LOCK:
        seq, prev_hash = _last_chained(path)
        head = _read_head(settings)
        records: list[tuple[str, dict]] = [(event, fields)]
        if _head_behind(head, seq, prev_hash) and _read_break(settings) is None:
            # The ledger was truncated, deleted or its tail rewritten. Record the old anchor in a sticky file
            # before this write moves the head, so verify_ledger keeps reporting the break (not laundered).
            detail = (f"{HEAD_FILE} anchored seq {(head or {}).get('seq')!r} but the ledger ends at seq {seq}; "
                      "entries were removed or rewritten")
            write_json_atomic(settings.state_dir / BREAK_FILE,
                              {"detected_at": iso_now(), "head": head, "ledger_seq": seq, "reason": detail})
            records.insert(0, ("ledger_tamper_detected", {"detail": detail}))
        entry: dict = {}
        for name, data in records:
            # Round-trip through JSON so the hashed form is exactly what a reader will parse back.
            entry = json.loads(json.dumps({"ts": iso_now(), "event": name, **data}, default=str))
            entry["seq"] = seq + 1
            entry["prev_hash"] = prev_hash
            entry["hash"] = _entry_hash(prev_hash, entry)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
            seq, prev_hash = entry["seq"], entry["hash"]
        # Anchor the head outside the file so a truncated tail or a deleted ledger is detectable. Best effort:
        # a head that lags (e.g. Windows briefly locks the file) still verifies, it only anchors less.
        try:
            write_json_atomic(settings.state_dir / HEAD_FILE, {"seq": entry["seq"], "hash": entry["hash"]})
        except OSError:
            pass


def _read_ledger(settings: Settings) -> list[str]:
    try:
        return _ledger_path(settings).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []


def _read_head(settings: Settings) -> dict | None:
    try:
        head = json.loads((settings.state_dir / HEAD_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"seq": None, "hash": None}
    return head if isinstance(head, dict) else {"seq": None, "hash": None}


def verify_ledger(settings: Settings) -> dict:
    """Walk the chain. Returns {"ok", "entries", "broken_at_seq", "reason"}.

    Unchained legacy lines are tolerated only before the first chained entry. The entry at the head
    anchor's seq must exist and carry the anchored hash (catches a truncated tail or a deleted ledger).
    """
    entries = 0
    expected_seq, prev_hash, chained = 1, GENESIS, False
    head = _read_head(settings)
    head_seq = head.get("seq") if head else None
    head_matched = head is None

    def broken(reason: str) -> dict:
        return {"ok": False, "entries": entries, "broken_at_seq": expected_seq, "reason": reason}

    for raw in _read_ledger(settings):
        if not raw.strip():
            continue
        entries += 1
        try:
            entry = json.loads(raw)
        except ValueError:
            return broken("unreadable line")
        if not isinstance(entry, dict):
            return broken("unreadable line")
        if "hash" not in entry:
            if chained:
                return broken("unchained legacy entries")
            continue
        chained = True
        if entry.get("seq") != expected_seq:
            return broken(f"sequence gap: expected seq {expected_seq}, found {entry.get('seq')!r}")
        if entry.get("prev_hash") != prev_hash:
            return broken("prev_hash does not match the previous entry (line removed or reordered)")
        if _entry_hash(prev_hash, entry) != entry.get("hash"):
            return broken("hash mismatch (entry was edited)")
        if head is not None and entry.get("seq") == head_seq:
            if entry.get("hash") != head.get("hash"):
                return broken("entry does not match the ledger head anchor (tail rewritten)")
            head_matched = True
        prev_hash = str(entry["hash"])
        expected_seq += 1
    if not head_matched:
        return broken(
            f"ledger truncated: {HEAD_FILE} records seq {head_seq!r} but the ledger ends at seq {expected_seq - 1}"
        )
    sticky = _read_break(settings)
    if sticky is not None:
        return {"ok": False, "entries": entries, "broken_at_seq": sticky.get("ledger_seq"),
                "reason": f"ledger was truncated or rewritten earlier ({sticky.get('reason')}; detected "
                          f"{sticky.get('detected_at')}, see {BREAK_FILE})"}
    return {"ok": True, "entries": entries, "broken_at_seq": None, "reason": None}


def _mentions(entry: dict, resource_id: str) -> bool:
    if entry.get("resource_id") == resource_id:
        return True
    for key in ("resource_ids", "approved_ids", "blocked"):
        value = entry.get(key)
        if isinstance(value, (list, dict)) and resource_id in value:
            return True
    results = entry.get("results")
    if isinstance(results, list):
        return any(isinstance(r, dict) and r.get("resource_id") == resource_id for r in results)
    return False


def history(settings: Settings, resource_id: str, limit: int = 50) -> list[dict]:
    """Newest-first ledger entries that mention resource_id (read from the ledger only, no AWS)."""
    if not isinstance(resource_id, str) or not resource_id.strip():
        return []
    rid = resource_id.strip()
    try:
        cap = max(0, int(limit))
    except (TypeError, ValueError):
        cap = 50
    out: list[dict] = []
    for raw in reversed(_read_ledger(settings)):
        if len(out) >= cap:
            break
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        if isinstance(entry, dict) and _mentions(entry, rid):
            if isinstance(entry.get("results"), list):
                # A scan lists every finding: keep only the rows about this resource.
                entry["results"] = [r for r in entry["results"] if isinstance(r, dict) and r.get("resource_id") == rid]
            out.append(entry)
    return out


# ---------------------------------------------------------------- Elastic IP quarantine evidence


def _ledger_entries(settings: Settings) -> list[dict]:
    out = []
    for raw in _read_ledger(settings):
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        if isinstance(entry, dict):
            out.append(entry)
    return out


def _void_recorded(settings: Settings, allocation_id: str, quarantined_at: str | None) -> dict | None:
    for entry in _ledger_entries(settings):
        if (entry.get("event") == "quarantine_void" and entry.get("resource_id") == allocation_id
                and entry.get("quarantined_at") == quarantined_at):
            return entry
    return None


def record_quarantine_void(settings: Settings, allocation_id: str, tags: dict[str, str], seen: str) -> None:
    """Record (once per quarantine) that a quarantined Elastic IP was seen in use: that quarantine is void."""
    at = tags.get(TAG_QUARANTINED_AT)
    if _void_recorded(settings, allocation_id, at) is None:
        audit(settings, "quarantine_void", resource_id=allocation_id, quarantined_at=at, detail=seen)


def _parse_iso(text: Any) -> datetime | None:
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def quarantine_problem(
    settings: Settings, allocation_id: str, tags: dict[str, str], now: datetime | None = None,
    require_over: bool = True,
) -> str | None:
    """Why this Elastic IP's quarantine cannot justify a release, or None if it can.

    The quarantine must be Warden's own (a done quarantine_address receipt recorded the same
    warden:quarantined-at), must not have been voided by the address being seen in use since, and its
    warden:quarantined-until tag must equal the window that receipt recorded. With require_over, that recorded
    window must also have ended: the tags are mutable, so the receipt (not the tag) decides when release is allowed.
    """
    at = tags.get(TAG_QUARANTINED_AT)
    if not at:
        return f"no {TAG_QUARANTINED_AT} tag - the quarantine was not set by Warden"
    matched: dict | None = None
    for summary in list_receipts(settings, limit=100_000):
        if summary.get("action") != "quarantine_address":
            continue
        receipt = load_receipt(settings, str(summary.get("receipt_id"))) or {}
        matched = next((r for r in receipt.get("results") or [] if r.get("resource_id") == allocation_id
                        and r.get("status") == "done" and r.get("quarantined_at") == at), None)
        if matched is not None:
            break
    if matched is None:
        return "the quarantine was not set by Warden (no matching quarantine receipt)"
    void = _void_recorded(settings, allocation_id, at)
    if void is not None:
        return f"it was in use again during its quarantine (seen {void.get('ts')}) - the quarantine is void"
    recorded = matched.get("quarantined_until")
    ends = _parse_iso(recorded)
    if ends is None or recorded != tags.get(TAG_QUARANTINED_UNTIL):
        return (f"its {TAG_QUARANTINED_UNTIL} tag ({tags.get(TAG_QUARANTINED_UNTIL)!r}) does not match the window "
                f"Warden recorded ({recorded!r}) - the quarantine tags were changed")
    if require_over and ends > (now or _utcnow()):
        return f"the quarantine window Warden recorded has not ended yet (ends {recorded})"
    return None


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
