"""Pure safety policy over resource tags (no AWS calls). Tags are untrusted data."""

from __future__ import annotations

import re
from typing import Mapping

from .config import Settings

MAX_TAG_LEN = 256
INJECTION_REASON = (
    "suspicious instruction-like text in tags (treated as data, never obeyed); needs human review"
)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ENV_KEYS = {"env", "environment", "stage"}
_PROD_VALUES = {"production", "prod"}
_LEGAL_HOLD_KEYS = {"legal-hold", "legal_hold", "legalhold"}
_MANAGED_BY_KEYS = {"managedby", "managed-by", "managed_by"}
_IAC_TOOLS = {"terraform", "cloudformation", "pulumi", "cdk", "crossplane"}
_MANAGED_KEYS = {
    "aws:cloudformation:stack-name": "managed by CloudFormation stack",
    "terraform": "managed by Terraform",
    "aws:autoscaling:groupname": "part of an Auto Scaling group",
    "eks:cluster-name": "part of an EKS cluster",
    "karpenter.sh/nodepool": "managed by Karpenter",
    "karpenter.sh/provisioner-name": "managed by Karpenter",
    "elasticbeanstalk:environment-name": "managed by Elastic Beanstalk",
}
_INJECTION = re.compile(
    r"\bignore\s+(?:(?:all|any|the)\s+)?(?:(?:previous|prior|above)\s+)?(?:rules|instructions|guardrails)\b"
    r"|\bdisregard\b"
    r"|\bsystem\s+prompt\b"
    r"|\byou\s+are\s+now\b"
    r"|\bact\s+as\b"
    r"|\bdelete\s+(?:all|every|everything)\b"
    r"|\boverride\b"
    r"|\bjailbreak\b"
    r"|\bdo\s+not\s+ask\b"
    r"|\bwithout\s+approval\b",
    re.IGNORECASE,
)


def tags_to_dict(tag_list: list[dict] | None) -> dict[str, str]:
    """Convert AWS [{'Key','Value'}] tags to a dict."""
    out: dict[str, str] = {}
    for tag in tag_list or []:
        key = tag.get("Key")
        if key is not None:
            out[str(key)] = str(tag.get("Value") or "")
    return out


def _clean(text: str) -> str:
    return _CONTROL_CHARS.sub("", str(text))[:MAX_TAG_LEN]


def sanitize_tags(tags: dict[str, str]) -> dict[str, str]:
    """Strip control characters and truncate keys/values to 256 chars."""
    return {_clean(k): _clean(v) for k, v in (tags or {}).items()}


def _lower(tags: Mapping[str, str]) -> dict[str, str]:
    return {str(k).strip().lower(): str(v).strip().lower() for k, v in (tags or {}).items()}


def protection_reasons(tags: Mapping[str, str]) -> list[str]:
    """Reasons a resource is protected (production, legal hold, DR, explicit protect)."""
    reasons: list[str] = []
    for key, value in _lower(tags).items():
        if key in _ENV_KEYS and value in _PROD_VALUES:
            reasons.append(f"protected: {key}={value} (production)")
        elif key in _LEGAL_HOLD_KEYS:
            reasons.append(f"protected: {key} tag present (legal hold)")
        elif (key == "dr" and value not in ("false", "no", "0")) or (key == "role" and value == "dr"):
            reasons.append(f"protected: {key}={value} (disaster recovery)")
        elif key == "warden:protect" and value == "true":
            reasons.append("protected: warden:protect=true")
    return reasons


def managed_by_reasons(tags: Mapping[str, str]) -> list[str]:
    """Reasons a resource is owned by IaC/autoscaling and must not be touched by hand."""
    reasons: list[str] = []
    for key, value in _lower(tags).items():
        if key in _MANAGED_KEYS:
            reasons.append(f"{_MANAGED_KEYS[key]} (tag {key}); would come back or break deploys")
        elif key in _MANAGED_BY_KEYS and value in _IAC_TOOLS:
            reasons.append(f"managed by {value} (tag {key}); would come back or break deploys")
    return reasons


def _normalise(text: str) -> str:
    return re.sub(r"[\s_\-]+", " ", str(text))


def injection_reasons(tags: Mapping[str, str]) -> list[str]:
    """Flag instruction-like tag text. Returns at most one reason."""
    for key, value in (tags or {}).items():
        if _INJECTION.search(_normalise(key)) or _INJECTION.search(_normalise(value)):
            return [INJECTION_REASON]
    return []


def keep_reasons(tags: Mapping[str, str]) -> list[str]:
    """All reasons to keep: protection, then managed-by, then injection."""
    return protection_reasons(tags) + managed_by_reasons(tags) + injection_reasons(tags)


def in_scope(tags: Mapping[str, str], settings: Settings) -> bool:
    """True if no scope tag is configured, or the resource carries it (case-insensitive)."""
    if not settings.scope_tag_key:
        return True
    want_key = settings.scope_tag_key.strip().lower()
    want_value = (settings.scope_tag_value or "").strip().lower()
    return _lower(tags).get(want_key) == want_value


def copyable_tags(tags: Mapping[str, str]) -> dict[str, str]:
    """Tags that may be re-written by us (AWS reserves the aws: prefix)."""
    return {k: v for k, v in (tags or {}).items() if not str(k).lower().startswith("aws:")}
