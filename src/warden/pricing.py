"""Static on-demand list-price estimates (USD). Not a bill: list-price estimates only."""

from __future__ import annotations

HOURS_PER_MONTH = 730
PRICING_NOTE = "list-price estimates (on-demand, Linux, no discounts or credits)"

_BASE_REGION = "us-east-1"

# Per-region EBS/snapshot/EIP rates.
_STORAGE: dict[str, dict[str, float]] = {
    "us-east-1": {
        "gp3": 0.08, "gp3_iops": 0.005, "gp3_throughput": 0.04,
        "gp2": 0.10, "io1": 0.125, "io2": 0.125, "provisioned_iops": 0.065,
        "st1": 0.045, "sc1": 0.015, "standard": 0.05,
        "snapshot": 0.05, "eip_hour": 0.005,
    },
    "ap-south-1": {
        "gp3": 0.0912, "gp3_iops": 0.0057, "gp3_throughput": 0.0456,
        "gp2": 0.114, "io1": 0.138, "io2": 0.138, "provisioned_iops": 0.072,
        "st1": 0.051, "sc1": 0.0174, "standard": 0.08,
        "snapshot": 0.05, "eip_hour": 0.005,
    },
}

# Hourly on-demand Linux instance prices.
_INSTANCES: dict[str, dict[str, float]] = {
    "us-east-1": {
        "t2.nano": 0.0058, "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464,
        "t2.large": 0.0928, "t2.xlarge": 0.1856,
        "t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
        "t3.large": 0.0832, "t3.xlarge": 0.1664,
        "t3a.nano": 0.0047, "t3a.micro": 0.0094, "t3a.small": 0.0188, "t3a.medium": 0.0376,
        "t3a.large": 0.0752, "t3a.xlarge": 0.1504,
        "t4g.nano": 0.0042, "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336,
        "t4g.large": 0.0672, "t4g.xlarge": 0.1344,
        "m5.large": 0.096, "m5.xlarge": 0.192, "m6i.large": 0.096, "m6i.xlarge": 0.192,
        "c5.large": 0.085, "c5.xlarge": 0.17, "r5.large": 0.126, "r5.xlarge": 0.252,
    },
    "ap-south-1": {
        "t2.nano": 0.0062, "t2.micro": 0.0124, "t2.small": 0.0248, "t2.medium": 0.0496,
        "t2.large": 0.0992, "t2.xlarge": 0.1984,
        "t3.nano": 0.0056, "t3.micro": 0.0112, "t3.small": 0.0224, "t3.medium": 0.0448,
        "t3.large": 0.0896, "t3.xlarge": 0.1792,
        "t3a.nano": 0.0051, "t3a.micro": 0.0101, "t3a.small": 0.0202, "t3a.medium": 0.0403,
        "t3a.large": 0.0806, "t3a.xlarge": 0.1613,
        "t4g.nano": 0.0045, "t4g.micro": 0.009, "t4g.small": 0.018, "t4g.medium": 0.0359,
        "t4g.large": 0.0718, "t4g.xlarge": 0.1437,
        "m5.large": 0.101, "m5.xlarge": 0.202, "m6i.large": 0.101, "m6i.xlarge": 0.202,
        "c5.large": 0.085, "c5.xlarge": 0.17, "r5.large": 0.128, "r5.xlarge": 0.256,
    },
}


def _rates(region: str) -> dict[str, float]:
    return _STORAGE.get(region, _STORAGE[_BASE_REGION])


def volume_monthly_usd(
    volume_type: str,
    size_gib: int,
    iops: int | None = None,
    throughput: int | None = None,
    region: str = "us-east-1",
) -> float:
    """Monthly list price of an EBS volume."""
    r = _rates(region)
    vtype = (volume_type or "gp2").lower()
    size = max(0, int(size_gib or 0))
    if vtype == "gp3":
        cost = size * r["gp3"]
        cost += max(0, int(iops or 0) - 3000) * r["gp3_iops"]
        cost += max(0, int(throughput or 0) - 125) * r["gp3_throughput"]
    elif vtype in ("io1", "io2"):
        cost = size * r[vtype] + max(0, int(iops or 0)) * r["provisioned_iops"]
    else:
        cost = size * r.get(vtype, r["gp2"])
    return round(cost, 2)


def snapshot_monthly_usd(size_gib: int, region: str = "us-east-1") -> float:
    """UPPER BOUND: snapshots bill on stored changed blocks, not the source volume size."""
    return round(max(0, int(size_gib or 0)) * _rates(region)["snapshot"], 2)


def address_monthly_usd(region: str = "us-east-1") -> float:
    """Monthly list price of one idle public IPv4 / Elastic IP."""
    return round(_rates(region)["eip_hour"] * HOURS_PER_MONTH, 2)


def instance_monthly_usd(instance_type: str, region: str = "us-east-1") -> float | None:
    """Monthly on-demand compute price, or None when the type is not in the table."""
    table = _INSTANCES.get(region, _INSTANCES[_BASE_REGION])
    hourly = table.get(instance_type) or _INSTANCES[_BASE_REGION].get(instance_type)
    if hourly is None:
        return None
    return round(hourly * HOURS_PER_MONTH, 2)
