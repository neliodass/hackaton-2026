import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from crypto.keygen import PRIVATE_KEY_PATH


def load_private_key() -> Ed25519PrivateKey:
    pem = PRIVATE_KEY_PATH.read_bytes()
    password = os.environ.get("SIGNING_KEY_PASSWORD")
    return load_pem_private_key(pem, password=password.encode() if password else None)


def canonical_manifest_bytes_from_dict(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
