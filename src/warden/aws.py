"""boto3 client factory and small AWS helpers."""

from __future__ import annotations

import time
from functools import cached_property
from typing import Any, Callable

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, WaiterError

from .config import Settings

_BOTO_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 8})
# Optional evidence APIs (CloudTrail, Recycle Bin, Route 53, ELBv2) fail fast: a slow or broken optional
# API must not push a tool call past the MCP request timeout (TrueForge aborts after 240 s).
_EVIDENCE_CONFIG = Config(retries={"mode": "standard", "total_max_attempts": 2}, connect_timeout=3, read_timeout=8)


class AwsClients:
    """Lazily created, cached boto3 clients for one region."""

    def __init__(self, settings: Settings, session: boto3.Session | None = None) -> None:
        self.settings = settings
        if session is None and settings.mock:
            # Dummy credentials: in mock mode real keys are never loaded, let alone sent anywhere.
            from .mock import MOCK_CREDENTIALS

            session = boto3.Session(region_name=settings.region, **MOCK_CREDENTIALS)
        self.session = session or boto3.Session(region_name=settings.region)
        self._account_id: str | None = None

    def client(self, service: str, config: Config | None = None) -> Any:
        """A new client for any service (real AWS, or the moto endpoint plus mock shims in mock mode)."""
        config = config or _BOTO_CONFIG
        if not self.settings.mock:
            return self.session.client(service, region_name=self.settings.region, config=config)
        from .mock import install_hooks

        client = self.session.client(service, region_name=self.settings.region, config=config,
                                     endpoint_url=self.settings.mock_endpoint)
        return install_hooks(service, client, self.settings)

    def _client(self, service: str, config: Config | None = None) -> Any:
        return self.client(service, config)

    @cached_property
    def ec2(self) -> Any:
        return self._client("ec2")

    @cached_property
    def cloudwatch(self) -> Any:
        return self._client("cloudwatch")

    @cached_property
    def cloudtrail(self) -> Any:
        return self._client("cloudtrail", _EVIDENCE_CONFIG)

    @cached_property
    def rbin(self) -> Any:
        return self._client("rbin", _EVIDENCE_CONFIG)

    @cached_property
    def route53(self) -> Any:
        return self._client("route53", _EVIDENCE_CONFIG)

    @cached_property
    def elbv2(self) -> Any:
        return self._client("elbv2", _EVIDENCE_CONFIG)

    @cached_property
    def sts(self) -> Any:
        return self._client("sts")

    def account_id(self) -> str:
        """Return the caller's AWS account id (cached)."""
        if self._account_id is None:
            self._account_id = self.sts.get_caller_identity()["Account"]
        return self._account_id


def error_code(err: Exception) -> str:
    """Return the AWS error code for a ClientError, else the exception class name."""
    if isinstance(err, ClientError):
        return str(err.response.get("Error", {}).get("Code") or "Unknown")
    return type(err).__name__


def wait_for(
    client: Any, waiter_name: str, delay: int, max_attempts: int, sleep: Callable[[float], Any] = time.sleep,
    **kwargs: Any,
) -> None:
    """client.get_waiter(name).wait(...), but retry *.NotFound (EC2 is eventually consistent right after a
    create; the snapshot_completed and volume_available waiters would otherwise fail on the first poll)."""
    attempts = max(1, max_attempts)
    while True:
        try:
            client.get_waiter(waiter_name).wait(WaiterConfig={"Delay": delay, "MaxAttempts": attempts}, **kwargs)
            return
        except WaiterError as err:
            code = str(((err.last_response or {}).get("Error") or {}).get("Code") or "")
            if not code.endswith("NotFound") or attempts <= 1:
                raise
            attempts -= 1
            sleep(delay)


def dry_run(call: Callable[..., Any], **kwargs: Any) -> str:
    """Run call(DryRun=True, **kwargs); summarise whether AWS would allow it."""
    try:
        call(DryRun=True, **kwargs)
    except ClientError as err:
        code = error_code(err)
        if code == "DryRunOperation":
            return "would_succeed"
        if code == "UnauthorizedOperation" or code.startswith("AccessDenied"):
            return f"denied: {code}"
        return f"error: {code}"
    except Exception as err:  # param validation, network, etc.
        return f"error: {error_code(err)}"
    # AWS always answers a DryRun with an error; a normal return means it was not honoured.
    return "error: DryRunNotHonoured"
