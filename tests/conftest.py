"""Shared fixtures: dummy AWS creds, isolated settings, moto-backed clients."""

from __future__ import annotations

import pytest
from moto import mock_aws

from warden.aws import AwsClients
from warden.config import load_settings

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let tests reach real AWS: dummy creds and a fixed region."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("WARDEN_FREEZE", "false")


@pytest.fixture
def settings(tmp_path):
    """Settings with state in tmp_path, region us-east-1, no scope tag."""
    return load_settings(env={"AWS_REGION": REGION, "WARDEN_STATE_DIR": str(tmp_path / "state")})


@pytest.fixture
def aws(settings):
    """AwsClients backed by moto."""
    with mock_aws():
        yield AwsClients(settings)


class _Clock:
    """A shared offset added to every clock Warden reads (datetime.now / time.time in its modules)."""

    def __init__(self) -> None:
        self.offset = 0.0

    def advance(self, seconds: float) -> None:
        self.offset += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """Let a test move Warden's wall clock forward, so a quarantine window passes for real.

    Every Warden module sees the same shifted time, so tags, receipts, plans and sign-offs stay consistent;
    nothing is back-dated or rewritten.
    """
    import time as real_time
    import types
    from datetime import datetime, timedelta

    from warden import actions, audit, plan, scanner, server, watchdog

    state = _Clock()

    class ShiftedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return datetime.now(tz) + timedelta(seconds=state.offset)

    shifted_time = types.SimpleNamespace(**{k: getattr(real_time, k) for k in dir(real_time) if not k.startswith("__")})
    shifted_time.time = lambda: real_time.time() + state.offset

    for module in (actions, audit, scanner, server, watchdog):
        if getattr(module, "datetime", None) is datetime:
            monkeypatch.setattr(module, "datetime", ShiftedDatetime)
    for module in (actions, plan, scanner, server, watchdog):
        if getattr(module, "time", None) is real_time:
            monkeypatch.setattr(module, "time", shifted_time)
    return state
