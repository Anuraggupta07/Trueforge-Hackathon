"""Runtime settings and shared tag constants for Warden."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]

# Tags Warden writes (all under the warden: namespace).
TAG_BACKUP_OF = "warden:backup-of"
TAG_EXPIRES_AT = "warden:expires-at"
TAG_RECYCLE = "warden:recycle"
TAG_RECYCLE_VALUE = "true"
TAG_RECYCLED_AT = "warden:recycled-at"
TAG_STOPPED_AT = "warden:stopped-at"
TAG_RESTORE_AZ = "warden:restore-az"
TAG_RESTORE_TYPE = "warden:restore-type"
TAG_RESTORE_SIZE = "warden:restore-size"
TAG_RESTORE_IOPS = "warden:restore-iops"
TAG_RESTORE_THROUGHPUT = "warden:restore-throughput"
TAG_PLAN_ID = "warden:plan-id"
TAG_RESTORED_FROM = "warden:restored-from"
TAG_QUARANTINED_AT = "warden:quarantined-at"
TAG_QUARANTINED_UNTIL = "warden:quarantined-until"
DEMO_TAG = ("warden:demo", "true")

_TRUE = {"1", "true", "yes", "on", "y"}
_FALSE = {"0", "false", "no", "off", "n", ""}


@dataclass(frozen=True)
class Settings:
    """Immutable Warden configuration."""

    region: str
    scope_tag_key: str | None
    scope_tag_value: str | None
    freeze: bool
    max_batch: int = 5
    idle_lookback_minutes: int = 43200
    idle_cpu_pct: float = 5.0
    idle_network_bytes_per_hour: float = 5_000_000
    backup_retention_days: int = 7
    plan_ttl_minutes: int = 60
    owner_lookup_limit: int = 25
    snapshot_wait_seconds: int = 600
    quarantine_minutes: int = 10080
    signoff_ttl_minutes: int = 10
    scan_budget_seconds: int = 90
    state_dir: Path = REPO_ROOT / ".warden"
    host: str = "127.0.0.1"
    port: int = 8000
    mock_endpoint: str | None = None  # WARDEN_MOCK_ENDPOINT: local moto server instead of real AWS

    @property
    def mock(self) -> bool:
        return self.mock_endpoint is not None

    @property
    def scope_label(self) -> str:
        """Human-readable scope, e.g. 'warden:demo=true' or 'all resources'."""
        if self.scope_tag_key is None:
            return "all resources"
        return f"{self.scope_tag_key}={self.scope_tag_value}"


FREEZE_FILE = "FREEZE"


def is_frozen(settings: Settings) -> bool:
    """WARDEN_FREEZE (read at start-up) or a <state_dir>/FREEZE file, checked on every call (no restart)."""
    return settings.freeze or (settings.state_dir / FREEZE_FILE).exists()


def _get(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _int(env: Mapping[str, str], name: str, default: int, minimum: int | None = 0) -> int:
    raw = _get(env, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = _get(env, name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None
    if value < 0 or value != value:
        raise ValueError(f"{name} must be a non-negative number, got {raw!r}")
    return value


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{name} must be true or false, got {raw!r}")


def _profile_region(env: Mapping[str, str]) -> str | None:
    """Region from the standard AWS config chain (AWS_PROFILE / ~/.aws/config), or None."""
    try:
        import boto3

        return boto3.Session(profile_name=_get(env, "AWS_PROFILE")).region_name
    except Exception:  # unknown profile, unreadable config...
        return None


def _scope(env: Mapping[str, str]) -> tuple[str | None, str | None]:
    raw = _get(env, "WARDEN_SCOPE_TAG")
    if raw is None:
        return None, None
    key, sep, value = raw.partition("=")
    key, value = key.strip(), value.strip()
    if not sep or not key or not value:
        raise ValueError(f"WARDEN_SCOPE_TAG must look like key=value, got {raw!r}")
    return key, value


def _mock_endpoint(env: Mapping[str, str]) -> str | None:
    raw = _get(env, "WARDEN_MOCK_ENDPOINT")
    if raw is None:
        return None
    if not raw.startswith(("http://", "https://")):
        raise ValueError(f"WARDEN_MOCK_ENDPOINT must be a URL like http://127.0.0.1:5000, got {raw!r}")
    return raw.rstrip("/")


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from env (or .env + os.environ when env is None)."""
    if env is None:
        from dotenv import load_dotenv

        load_dotenv(REPO_ROOT / ".env")
        env = os.environ
    scope_key, scope_value = _scope(env)
    max_batch = min(20, max(1, _int(env, "WARDEN_MAX_BATCH", 5, minimum=None)))
    state_raw = _get(env, "WARDEN_STATE_DIR")
    return Settings(
        region=(_get(env, "AWS_REGION") or _get(env, "AWS_DEFAULT_REGION") or _profile_region(env)
                or "us-east-1"),
        scope_tag_key=scope_key,
        scope_tag_value=scope_value,
        freeze=_bool(env, "WARDEN_FREEZE", False),
        max_batch=max_batch,
        idle_lookback_minutes=_int(env, "WARDEN_IDLE_LOOKBACK_MINUTES", 43200, minimum=5),
        idle_cpu_pct=_float(env, "WARDEN_IDLE_CPU_PCT", 5.0),
        idle_network_bytes_per_hour=_float(env, "WARDEN_IDLE_NETWORK_BYTES_PER_HOUR", 5_000_000),
        backup_retention_days=_int(env, "WARDEN_BACKUP_RETENTION_DAYS", 7, minimum=1),
        plan_ttl_minutes=_int(env, "WARDEN_PLAN_TTL_MINUTES", 60, minimum=1),
        owner_lookup_limit=_int(env, "WARDEN_OWNER_LOOKUP_LIMIT", 25, minimum=0),
        snapshot_wait_seconds=_int(env, "WARDEN_SNAPSHOT_WAIT_SECONDS", 600, minimum=5),
        quarantine_minutes=_int(env, "WARDEN_QUARANTINE_MINUTES", 10080, minimum=1),
        signoff_ttl_minutes=_int(env, "WARDEN_SIGNOFF_TTL_MINUTES", 10, minimum=1),
        scan_budget_seconds=_int(env, "WARDEN_SCAN_BUDGET_SECONDS", 90, minimum=10),
        state_dir=Path(state_raw).expanduser() if state_raw else REPO_ROOT / ".warden",
        host=_get(env, "WARDEN_HOST") or "127.0.0.1",
        port=_int(env, "WARDEN_PORT", 8000, minimum=1),
        mock_endpoint=_mock_endpoint(env),
    )
