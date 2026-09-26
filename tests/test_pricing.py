from warden import pricing


def test_gp3_base_and_extras():
    assert pricing.volume_monthly_usd("gp3", 100) == 8.0
    # 1000 extra iops * 0.005 + 25 extra MB/s * 0.04
    assert pricing.volume_monthly_usd("gp3", 100, iops=4000, throughput=150) == 8.0 + 5.0 + 1.0


def test_other_volume_types():
    assert pricing.volume_monthly_usd("gp2", 10) == 1.0
    assert pricing.volume_monthly_usd("io1", 10, iops=100) == round(1.25 + 6.5, 2)
    assert pricing.volume_monthly_usd("st1", 1000) == 45.0
    assert pricing.volume_monthly_usd("sc1", 1000) == 15.0
    assert pricing.volume_monthly_usd("standard", 10) == 0.5


def test_snapshot_address_instance():
    assert pricing.snapshot_monthly_usd(20) == 1.0
    assert pricing.address_monthly_usd() == 3.65
    assert pricing.instance_monthly_usd("t3.micro") == round(0.0104 * 730, 2)
    assert pricing.instance_monthly_usd("x9.huge") is None
    assert pricing.HOURS_PER_MONTH == 730


def test_regions():
    assert pricing.volume_monthly_usd("gp3", 100, region="ap-south-1") > pricing.volume_monthly_usd("gp3", 100)
    assert pricing.volume_monthly_usd("gp3", 100, region="mars-1") == pricing.volume_monthly_usd("gp3", 100)
    assert pricing.instance_monthly_usd("t3.micro", region="mars-1") == pricing.instance_monthly_usd("t3.micro")
