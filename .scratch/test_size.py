import json, sys, asyncio
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from test_scripts import FakeRbin, rbin, lt_volume_tags  # noqa
from test_scripts import _plant
from warden import scanner, server

def test_size(aws, settings, rbin):
    _plant(aws, settings)
    server.configure(settings, aws)
    res = asyncio.run(server.server.call_tool("scan_for_waste", {}))
    sc = res.structured_content
    txt = json.dumps(sc)
    print("\nbytes", len(txt), "approx tokens", len(txt)//4, "findings", len(sc["findings"]))
    print("first100:", txt[:100])
    print("summary", sc["summary"])
    for f in sc["findings"]:
        print(f["resource_type"], f["verdict"], f["action"], f["name"], f["reasons"][:1], f["evidence"]["dry_run"])
    print("text content len", len(res.content[0].text))
