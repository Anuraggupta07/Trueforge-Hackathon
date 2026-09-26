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
    for name in ("actions.py", "scanner.py", "server.py", "watchdog.py"):
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


SERVICE_PREFIX = {"route53": "route53", "r53": "route53", "elbv2": "elasticloadbalancing"}


def _other_calls() -> set[str]:
    """Route 53 / ELBv2 operations, called directly (client.op) or through _paginate(client, "op")."""
    ops: set[str] = set()
    for name in ("actions.py", "scanner.py", "server.py", "watchdog.py"):
        src = (ROOT / "src" / "warden" / name).read_text(encoding="utf-8")
        for client, op in re.findall(r"\b(route53|r53|elbv2)(?:\.|,\s*\")([a-z_]+)", src):
            if op not in NOT_API:
                ops.add(SERVICE_PREFIX[client] + ":" + "".join(p.capitalize() for p in op.split("_")))
    return ops


def test_every_route53_and_elbv2_call_is_allowed():  # v1.1 DNS / load balancer checks
    calls = _other_calls()
    assert calls == {
        "route53:ListHostedZones", "route53:ListResourceRecordSets",
        "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth",
    }
    assert [c for c in calls if not _allows(c)] == []


def test_elastic_ip_tags_are_warden_keys_only():  # v1.1 EIP quarantine
    eip = "arn:aws:ec2:*:*:elastic-ip/*"
    for action in ("ec2:CreateTags", "ec2:DeleteTags"):
        stmts = [s for s in _allows(action) if eip in (s["Resource"] if isinstance(s["Resource"], list) else [s["Resource"]])]
        assert stmts, action
        for s in stmts:
            assert s["Condition"]["ForAllValues:StringLike"]["aws:TagKeys"] == ["warden:*"]
            assert s["Condition"]["Null"]["aws:TagKeys"] == "false"


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


PROTECT_KEY = "warden:protect"


def test_protect_tag_writes_are_explicitly_denied():  # finding 14: warden:protect sits inside warden:*
    denies = [
        s for s in STATEMENTS
        if s["Effect"] == "Deny" and {"ec2:CreateTags", "ec2:DeleteTags"} <= set(_actions(s))
    ]
    assert denies, "no Deny on CreateTags/DeleteTags"
    (deny,) = denies
    assert deny["Resource"] == "*"
    assert deny["Condition"] == {"ForAnyValue:StringEqualsIgnoreCase": {"aws:TagKeys": [PROTECT_KEY]}}


def _condition_holds(op: str, key: str, want, ctx: dict) -> bool:
    """Evaluate one condition operator against a request context (only the operators this policy uses)."""
    wants = [str(w) for w in (want if isinstance(want, list) else [want])]
    have = ctx.get(key)
    if op == "Null":
        return (have is None) == (wants[0] == "true")
    if have is None:
        return op.startswith("ForAllValues:")  # IAM: ForAllValues over an empty set is true, anything else false
    values = have if isinstance(have, list) else [have]
    if op == "StringEquals":
        return any(v in wants for v in values)
    if op == "ForAllValues:StringLike":
        return all(any(fnmatch.fnmatchcase(v, w) for w in wants) for v in values)
    if op == "ForAnyValue:StringEqualsIgnoreCase":
        return any(v.lower() in {w.lower() for w in wants} for v in values)
    if op == "StringLike":
        return any(fnmatch.fnmatchcase(v, w) for v in values for w in wants)
    if op == "Bool":
        return any(v.lower() == wants[0].lower() for v in values)
    raise AssertionError(f"unexpected operator {op}")


def _tag_request_allowed(action: str, keys: list[str], resource: str, create_action: str | None = None) -> bool:
    """Explicit Deny wins, then any matching Allow (IAM evaluation for one tag request)."""
    ctx: dict = {"aws:TagKeys": keys or None}
    if create_action:
        ctx["ec2:CreateAction"] = create_action

    def matches(stmt: dict) -> bool:
        resources = stmt["Resource"] if isinstance(stmt["Resource"], list) else [stmt["Resource"]]
        if not any(fnmatch.fnmatch(action, a) for a in _actions(stmt)):
            return False
        if not any(r == "*" or fnmatch.fnmatch(resource, r) for r in resources):
            return False
        return all(
            _condition_holds(op, key, want, ctx)
            for op, pairs in (stmt.get("Condition") or {}).items() for key, want in pairs.items()
        )

    if any(matches(s) for s in STATEMENTS if s["Effect"] == "Deny"):
        return False
    return any(matches(s) for s in STATEMENTS if s["Effect"] == "Allow")


VOLUME_ARN = "arn:aws:ec2:us-east-1:123456789012:volume/vol-1"


@pytest.mark.parametrize("action", ["ec2:CreateTags", "ec2:DeleteTags"])
@pytest.mark.parametrize("keys", [[PROTECT_KEY], ["Warden:Protect"], ["WARDEN:PROTECT"], ["warden:stopped-at", PROTECT_KEY]])
def test_warden_cannot_write_or_remove_the_protect_tag(action, keys):  # finding 14
    for resource in (VOLUME_ARN, "arn:aws:ec2:us-east-1::snapshot/snap-1",
                     "arn:aws:ec2:us-east-1:123456789012:instance/i-1",
                     "arn:aws:ec2:us-east-1:123456789012:elastic-ip/eipalloc-1"):
        assert not _tag_request_allowed(action, keys, resource), (action, keys, resource)


def test_protect_tag_cannot_be_planted_on_create():  # finding 14: tag-on-create goes through ec2:CreateTags too
    assert not _tag_request_allowed("ec2:CreateTags", ["Name", PROTECT_KEY], VOLUME_ARN, create_action="CreateVolume")
    assert _tag_request_allowed("ec2:CreateTags", ["Name", "warden:restored-from"], VOLUME_ARN, create_action="CreateVolume")


@pytest.mark.parametrize("action", ["ec2:CreateTags", "ec2:DeleteTags"])
def test_warden_bookkeeping_tags_still_allowed(action):  # the new Deny must not block Warden's own tags
    for key in ("warden:stopped-at", "warden:recycle", "warden:quarantined-until", "warden:human-undo-at"):
        assert _tag_request_allowed(action, [key], VOLUME_ARN), key
    assert not _tag_request_allowed(action, ["Name"], VOLUME_ARN)  # still only warden:* keys


_OPERATORS = {
    "StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "StringLike",
    "StringNotLike", "NumericEquals", "NumericLessThan", "NumericGreaterThan", "Bool", "Null", "ArnLike", "ArnEquals",
    "DateLessThan", "DateGreaterThan", "IpAddress",
}
_MULTIVALUED_KEYS = {"aws:TagKeys"}


def test_policy_is_valid_iam_grammar():
    assert set(POLICY) == {"Version", "Statement"} and POLICY["Version"] == "2012-10-17"
    assert isinstance(STATEMENTS, list) and STATEMENTS
    sids = [s.get("Sid") for s in STATEMENTS]
    assert len(set(sids)) == len(sids)
    for s in STATEMENTS:
        sid = s.get("Sid")
        assert isinstance(sid, str) and re.fullmatch(r"[A-Za-z0-9]+", sid), sid
        assert set(s) <= {"Sid", "Effect", "Action", "Resource", "Condition"}, sid
        assert {"Effect", "Action", "Resource"} <= set(s), sid
        assert s["Effect"] in ("Allow", "Deny"), sid
        acts = _actions(s)
        assert acts and all(isinstance(a, str) and re.fullmatch(r"[a-z0-9-]+:[A-Za-z0-9*]+", a) for a in acts), sid
        assert len(set(acts)) == len(acts), sid
        resources = s["Resource"] if isinstance(s["Resource"], list) else [s["Resource"]]
        assert resources and all(r == "*" or re.fullmatch(r"arn:aws:[a-z0-9-]+:[^:]*:[^:]*:.+", r) for r in resources), sid
        for op, pairs in (s.get("Condition") or {}).items():
            prefix, _, base = op.rpartition(":") if op.startswith(("ForAllValues:", "ForAnyValue:")) else ("", "", op)
            base = base[: -len("IfExists")] if base.endswith("IfExists") else base
            assert base in _OPERATORS, (sid, op)
            assert isinstance(pairs, dict) and pairs, (sid, op)
            for key, want in pairs.items():
                assert re.fullmatch(r"[a-z0-9]+:[A-Za-z0-9]+(/[A-Za-z0-9_.:/=+@-]+)?", key), (sid, key)
                # Set operators only make sense on multivalued keys; single-valued keys must not use them.
                assert bool(prefix) == (key in _MULTIVALUED_KEYS and base != "Null"), (sid, op, key)
                values = want if isinstance(want, list) else [want]
                assert values and all(isinstance(v, str) for v in values), (sid, key)
                if base in ("Bool", "Null"):
                    assert values in (["true"], ["false"]), (sid, key)


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
