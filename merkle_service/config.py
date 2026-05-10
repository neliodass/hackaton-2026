import os
from pathlib import Path

HOST = os.environ.get("MERKLE_SERVICE_HOST", "127.0.0.1")
PORT = int(os.environ.get("MERKLE_SERVICE_PORT", "9001"))

_default_log = Path(__file__).resolve().parent / "log.json"
LOG_PATH = Path(os.environ.get("MERKLE_LOG_PATH", str(_default_log)))
