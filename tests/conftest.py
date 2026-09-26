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
