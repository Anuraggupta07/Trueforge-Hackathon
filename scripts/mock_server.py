"""Start a local moto server for Warden's mock mode (the fallback when no AWS account is available).

Run:  uv run python scripts/mock_server.py            (listens on 127.0.0.1:5000; Ctrl+C stops it)
Then: set WARDEN_MOCK_ENDPOINT=http://127.0.0.1:5000 in .env and use plant.py, the MCP server and
reset.py exactly as with real AWS. moto keeps everything in memory, so a restart starts empty; the
simulated Recycle Bin state is cleared at start-up to match.
"""

from __future__ import annotations

import argparse
import threading

import _common  # noqa: F401  (sets up sys.path if needed)
from warden import mock
from warden.config import load_settings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="port (default 5000)")
    args = parser.parse_args()

    from moto.server import ThreadedMotoServer

    settings = load_settings()
    mock.reset_state(settings)
    server = ThreadedMotoServer(ip_address=args.host, port=args.port, verbose=False)
    server.start()
    endpoint = f"http://{args.host}:{args.port}"
    print(f"moto server running at {endpoint} (in memory; Ctrl+C to stop)")
    if settings.mock_endpoint != endpoint:
        print(f"Set WARDEN_MOCK_ENDPOINT={endpoint} in .env to point Warden at it "
              f"(currently {settings.mock_endpoint or 'unset, i.e. real AWS'}).")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("Stopping moto server.")
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
