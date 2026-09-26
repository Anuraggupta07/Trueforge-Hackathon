"""Tests for the hash-chained ledger in warden.audit (audit.jsonl)."""

from __future__ import annotations

import json
import threading

from warden import audit


def _path(settings):
    return settings.state_dir / "audit.jsonl"


def _lines(settings) -> list[dict]:
    return [json.loads(line) for line in _path(settings).read_text(encoding="utf-8").splitlines()]


def test_chain_fields_and_integrity(settings):
    for i in range(5):
        audit.audit(settings, "scan", plan_id=f"plan-{i}", obj=object())
    lines = _lines(settings)
    assert [e["seq"] for e in lines] == [1, 2, 3, 4, 5]
    assert lines[0]["prev_hash"] == "GENESIS"
    for prev, cur in zip(lines, lines[1:]):
        assert cur["prev_hash"] == prev["hash"]
    assert all(len(e["hash"]) == 64 for e in lines)
    assert audit.verify_ledger(settings) == {"ok": True, "entries": 5, "broken_at_seq": None, "reason": None}


def test_missing_and_empty_ledger(settings):
    assert audit.verify_ledger(settings)["ok"] is True
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    _path(settings).write_text("", encoding="utf-8")
    assert audit.verify_ledger(settings) == {"ok": True, "entries": 0, "broken_at_seq": None, "reason": None}
    audit.audit(settings, "first")
    assert _lines(settings)[0]["seq"] == 1 and audit.verify_ledger(settings)["ok"]


def test_tampered_middle_line_is_detected(settings):
    for i in range(5):
        audit.audit(settings, "action_item", resource_id=f"vol-{i}", status="done")
    raw = _path(settings).read_text(encoding="utf-8").splitlines()
    entry = json.loads(raw[2])
    entry["status"] = "skipped"  # rewrite history without re-hashing
    raw[2] = json.dumps(entry)
    _path(settings).write_text("\n".join(raw) + "\n", encoding="utf-8")
    result = audit.verify_ledger(settings)
    assert result["ok"] is False and result["broken_at_seq"] == 3 and "edited" in result["reason"]


def test_deleted_line_is_detected(settings):
    for i in range(4):
        audit.audit(settings, "e", n=i)
    raw = _path(settings).read_text(encoding="utf-8").splitlines()
    del raw[1]
    _path(settings).write_text("\n".join(raw) + "\n", encoding="utf-8")
    result = audit.verify_ledger(settings)
    assert result["ok"] is False and result["broken_at_seq"] == 2


def test_rehashed_forgery_still_breaks_the_next_link(settings):
    for i in range(3):
        audit.audit(settings, "e", n=i)
    raw = _path(settings).read_text(encoding="utf-8").splitlines()
    entry = json.loads(raw[0])
    entry["n"] = 99
    entry["hash"] = audit._entry_hash(entry["prev_hash"], entry)  # attacker recomputes this line only
    raw[0] = json.dumps(entry)
    _path(settings).write_text("\n".join(raw) + "\n", encoding="utf-8")
    result = audit.verify_ledger(settings)
    assert result["ok"] is False and result["broken_at_seq"] == 2


def test_concurrent_appends_keep_a_valid_chain(settings):
    def worker(n: int) -> None:
        for i in range(25):
            audit.audit(settings, "e", worker=n, i=i)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = audit.verify_ledger(settings)
    assert result == {"ok": True, "entries": 200, "broken_at_seq": None, "reason": None}
    assert [e["seq"] for e in _lines(settings)] == list(range(1, 201))


def test_legacy_prefix_ok_but_legacy_after_chain_is_not(settings):
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    _path(settings).write_text(json.dumps({"ts": "x", "event": "old"}) + "\n", encoding="utf-8")
    audit.audit(settings, "new")
    audit.audit(settings, "new2")
    assert _lines(settings)[1]["seq"] == 1 and _lines(settings)[1]["prev_hash"] == "GENESIS"
    assert audit.verify_ledger(settings)["ok"] is True
    with open(_path(settings), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": "y", "event": "sneaky"}) + "\n")
    result = audit.verify_ledger(settings)
    assert result["ok"] is False and result["reason"] == "unchained legacy entries" and result["broken_at_seq"] == 3


def test_tail_read_spans_chunks(settings, monkeypatch):
    monkeypatch.setattr(audit, "_TAIL_CHUNK", 16)
    for i in range(4):
        audit.audit(settings, "e", padding="x" * 100, n=i)
    assert [e["seq"] for e in _lines(settings)] == [1, 2, 3, 4]
    assert audit.verify_ledger(settings)["ok"]


def test_history_filters_and_orders_newest_first(settings):
    audit.audit(settings, "scan", plan_id="plan-1")
    audit.audit(settings, "action_item", resource_id="vol-1", status="done")
    audit.audit(settings, "watchdog_signoff", approved_ids=["vol-1", "vol-2"], blocked={})
    audit.audit(settings, "watchdog_block", blocked={"vol-1": "production"})
    audit.audit(settings, "watchdog_signoff_consumed", resource_ids=["vol-1"])
    audit.audit(settings, "receipt", results=[{"resource_id": "vol-1"}, {"resource_id": "vol-3"}])
    audit.audit(settings, "action_item", resource_id="vol-10", status="done")  # no substring matches

    events = [e["event"] for e in audit.history(settings, "vol-1")]
    assert events == [
        "receipt", "watchdog_signoff_consumed", "watchdog_block", "watchdog_signoff", "action_item",
    ]
    assert [e["event"] for e in audit.history(settings, "vol-1", limit=2)] == ["receipt", "watchdog_signoff_consumed"]
    assert [e["event"] for e in audit.history(settings, "vol-2")] == ["watchdog_signoff"]
    assert audit.history(settings, "vol-404") == []
    assert audit.history(settings, "") == []


# ---------------------------------------------------------------- review fixes


def test_truncated_tail_is_detected(settings):  # bypass F2 / demo F5
    for i in range(6):
        audit.audit(settings, "e", n=i)
    raw = _path(settings).read_text(encoding="utf-8").splitlines()
    _path(settings).write_text("\n".join(raw[:2]) + "\n", encoding="utf-8")
    result = audit.verify_ledger(settings)
    assert result["ok"] is False and "truncated" in result["reason"] and result["broken_at_seq"] == 3


def test_deleted_ledger_is_detected(settings):  # bypass F2 / demo F5
    audit.audit(settings, "e")
    _path(settings).unlink()
    result = audit.verify_ledger(settings)
    assert result["ok"] is False and "truncated" in result["reason"]


def test_rewritten_tail_is_detected(settings):  # a re-hashed last line no longer matches the head anchor
    for i in range(3):
        audit.audit(settings, "e", n=i)
    raw = _path(settings).read_text(encoding="utf-8").splitlines()
    entry = json.loads(raw[-1])
    entry["n"] = 99
    entry["hash"] = audit._entry_hash(entry["prev_hash"], entry)
    raw[-1] = json.dumps(entry)
    _path(settings).write_text("\n".join(raw) + "\n", encoding="utf-8")
    result = audit.verify_ledger(settings)
    assert result["ok"] is False and result["broken_at_seq"] == 3


def test_history_narrows_results_to_the_resource(settings):  # bypass F3 / demo F1
    audit.audit(settings, "scan", plan_id="plan-1", results=[
        {"resource_id": "vol-prod", "verdict": "keep", "tier": "protected"},
        {"resource_id": "vol-other", "verdict": "act", "tier": "safe_reversible"},
    ])
    (entry,) = audit.history(settings, "vol-prod")
    assert entry["event"] == "scan" and entry["results"] == [
        {"resource_id": "vol-prod", "verdict": "keep", "tier": "protected"}
    ]
