import os
from pathlib import Path

HOST = os.environ.get("UPDATE_SERVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("UPDATE_SERVER_PORT", "8000"))
SIGNING_MACHINE_URL = os.environ.get("SIGNING_MACHINE_URL", "http://127.0.0.1:9000")
MERKLE_SERVICE_URL = os.environ.get("MERKLE_SERVICE_URL", "http://127.0.0.1:9001")

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "packages"
MANIFEST_PATH = PACKAGE_DIR / "manifest.json"
MANIFEST_SIG_PATH = PACKAGE_DIR / "manifest.sig"
MANIFEST_PQ_SIG_PATH = PACKAGE_DIR / "manifest.pq.sig"
SIGNING_CERT_PATH = PACKAGE_DIR / "signing_cert.json"
UPDATE_PACKAGE_PATH = PACKAGE_DIR / "update.zip"

VERSIONS_DIR = PACKAGE_DIR / "versions"
LATEST_POINTER_PATH = PACKAGE_DIR / "latest.json"
