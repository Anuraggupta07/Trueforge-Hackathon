"""Pure safety policy over resource tags (no AWS calls). Tags are untrusted data."""

from __future__ import annotations

import re
import unicodedata
from typing import Mapping

from .config import Settings

MAX_TAG_LEN = 256
INJECTION_REASON = (
    "suspicious instruction-like text in tags (treated as data, never obeyed); needs human review"
)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ENV_KEYS = {"env", "environment", "stage"}
# prod, prd, production, alone or followed by a separator (prod-eu, Production_US, prd.1).
_PROD_VALUE = re.compile(r"^(?:prod|prd|production)(?:[-_ .:/].*)?$")
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
    "eks:nodegroup-name": "part of an EKS node group",
    "ebs.csi.aws.com/cluster": "a Kubernetes (EBS CSI) volume",
    "csivolumename": "a Kubernetes (EBS CSI) volume",
    "kubernetescluster": "part of a Kubernetes cluster",
    "aws:backup:source-resource": "managed by AWS Backup",
    "aws:dlm:lifecycle-policy-id": "managed by Data Lifecycle Manager",
}
# Keys that embed a cluster or claim name, so they must be matched by prefix.
_MANAGED_PREFIXES = {
    "kubernetes.io/cluster/": "part of a Kubernetes cluster",
    "kubernetes.io/created-for/": "a Kubernetes persistent volume",
}
_INJECTION = re.compile(
    r"\b(?:ignore|forget|disregard|bypass|skip)\s+(?:(?:all|any|the|your|my|of|previous|prior|above|earlier|"
    r"these|those|safety|system)\s+)*(?:rules|instructions|guardrails|prompts?|policy|policies|checks)\b"
    r"|\bdisregard\b"
    r"|\badmin\s+mode\b"
    r"|^\s*(?:system|assistant)\s*:"
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
        if key in _ENV_KEYS and _PROD_VALUE.match(value):
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
        prefix = next((p for p in _MANAGED_PREFIXES if key.startswith(p)), None)
        if key in _MANAGED_KEYS:
            reasons.append(f"{_MANAGED_KEYS[key]} (tag {key}); would come back or break deploys")
        elif prefix:
            reasons.append(f"{_MANAGED_PREFIXES[prefix]} (tag {key}); would come back or break deploys")
        elif key in _MANAGED_BY_KEYS and value in _IAC_TOOLS:
            reasons.append(f"managed by {value} (tag {key}); would come back or break deploys")
    return reasons


# Common Cyrillic/Greek look-alikes of Latin letters (after NFKD).
_CONFUSABLES = str.maketrans("аеорсухіѕјοαει",
                             "aeopcyxisjoaei")


def _fold(text: str) -> str:
    """NFKD-fold, drop invisible/format chars and accents, map look-alikes (keeps punctuation)."""
    decomposed = unicodedata.normalize("NFKD", str(text))
    kept = "".join(ch for ch in decomposed if unicodedata.category(ch) not in ("Cf", "Mn", "Cc"))
    return kept.lower().translate(_CONFUSABLES)


def _normalise(text: str) -> str:
    """Folded text with all punctuation and separators collapsed to single spaces."""
    return re.sub(r"[\W_]+", " ", _fold(text)).strip()


def injection_reasons(tags: Mapping[str, str]) -> list[str]:
    """Flag instruction-like tag text. Returns at most one reason."""
    for key, value in (tags or {}).items():
        for text in (key, value):
            if _INJECTION.search(_normalise(text)) or _INJECTION.search(_fold(text)):
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
