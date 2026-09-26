"""The shipped IAM policy must allow every EC2 call Warden makes, and deny what the README says it denies."""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "iam" / "warden-policy.json").read_text(encoding="utf-8"))
STATEMENTS = POLICY["Statement"]
NOT_API = {"get_waiter", "get_paginator", "can_paginate", "exceptions", "meta"}
DESTRUCTIVE = {"ec2:DeleteVolume", "ec2:DeleteSnapshot", "ec2:StopInstances", "ec2:ReleaseAddress"}


def _actions(stmt: dict) -> list[str]:
    acts = stmt["Action"]
    return [acts] if isinstance(acts, str) else list(acts)


def _allows(action: str) -> list[dict]:
    return [s for s in STATEMENTS if s["Effect"] == "Allow" and any(fnmatch.fnmatch(action, a) for a in _actions(s))]


def _ec2_calls() -> set[str]:
    ops: set[str] = set()
    for name in ("actions.py", "scanner.py", "server.py"):
        src = (ROOT / "src" / "warden" / name).read_text(encoding="utf-8")
        ops |= {m for m in re.findall(r"\bec2\.([a-z_]+)\b", src) if m not in NOT_API}
    return ops


def _iam_name(op: str) -> str:
    return "ec2:" + "".join(part.capitalize() for part in op.split("_"))


def test_every_ec2_call_is_allowed():  # S2 / F6 / RA-6
    calls = _ec2_calls()
    assert "delete_tags" in calls and "create_snapshot" in calls
    missing = sorted(_iam_name(op) for op in calls if not _allows(_iam_name(op)))
    assert missing == []


def test_delete_tags_only_for_warden_keys():  # S2
    stmts = _allows("ec2:DeleteTags")
    assert stmts
    for s in stmts:
        cond = s["Condition"]
        assert cond["ForAllValues:StringLike"]["aws:TagKeys"] == ["warden:*"]
        assert cond["Null"]["aws:TagKeys"] == "false"  # DeleteTags without Tags would delete every tag


def test_create_tags_cannot_rewrite_protection_tags():  # S15
    for s in _allows("ec2:CreateTags"):
        cond = s.get("Condition") or {}
        on_create = set((cond.get("StringEquals") or {}).get("ec2:CreateAction") or [])
        warden_only = (cond.get("ForAllValues:StringLike") or {}).get("aws:TagKeys") == ["warden:*"]
        assert warden_only or on_create <= {"CreateSnapshot", "CreateVolume"} and on_create, s["Sid"]


def _deny_conditions() -> list[dict]:
    return [
        s["Condition"] for s in STATEMENTS
        if s["Effect"] == "Deny" and DESTRUCTIVE <= set(_actions(s)) and "Condition" in s
    ]


def _denied(tags: dict[str, str]) -> bool:
    """Tiny evaluator for the condition operators this policy uses (AND within one statement)."""
    for cond in _deny_conditions():
        results = []
        for op, pairs in cond.items():
            for key, want in pairs.items():
                tag = key.split("/", 1)[1] if key.startswith("aws:ResourceTag/") else None
                have = tags.get(tag) if tag else None
                wants = want if isinstance(want, list) else [want]
                if op == "Null":
                    results.append((have is None) == (wants[0] == "true"))
                elif op == "StringEqualsIgnoreCase":
                    results.append(have is not None and have.lower() in {w.lower() for w in wants})
                elif op == "StringNotEqualsIgnoreCase":
                    results.append(have is None or have.lower() not in {w.lower() for w in wants})
                elif op == "StringLike":
                    results.append(have is not None and any(fnmatch.fnmatchcase(have, w) for w in wants))
                else:
                    raise AssertionError(f"unexpected operator {op}")
        if all(results):
            return True
    return False


@pytest.mark.parametrize(
    "tags",
    [
        {"env": "production"}, {"env": "PROD"}, {"env": "prd"}, {"environment": "Production-EU"},
        {"stage": "prod"}, {"legal-hold": "x"}, {"legal_hold": "x"}, {"legalhold": "2026"},
        {"dr": "true"}, {"dr": "yes"}, {"role": "dr"}, {"role": "DR"}, {"warden:protect": "true"},
    ],
)
def test_iam_denies_what_the_code_protects(tags):  # S6 / RA-7 / S16
    from warden import policy

    assert policy.protection_reasons(tags), tags
    assert _denied(tags), tags


@pytest.mark.parametrize("tags", [{}, {"env": "dev"}, {"dr": "false"}, {"role": "web"}])
def test_iam_allows_unprotected(tags):
    assert not _denied(tags)


def test_kms_use_only_through_ebs():  # S11
    stmts = _allows("kms:CreateGrant")
    assert stmts
    for s in stmts:
        assert s["Condition"]["StringLike"]["kms:ViaService"] == "ec2.*.amazonaws.com"
    assert not _allows("kms:ScheduleKeyDeletion") and not _allows("kms:PutKeyPolicy")


def test_policy_fits_managed_policy_size_limit():
    text = (ROOT / "iam" / "warden-policy.json").read_text(encoding="utf-8")
    assert len(re.sub(r"\s", "", text)) <= 6144
