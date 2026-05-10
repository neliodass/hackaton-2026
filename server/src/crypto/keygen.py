from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

_KEYS_ROOT = Path(__file__).resolve().parent.parent.parent.parent / "keys"
KEYS_PRIVATE_DIR = _KEYS_ROOT / "private"
PRIVATE_KEY_PATH = KEYS_PRIVATE_DIR / "ed25519_signing_sk.pem"


def generate_keys(password: bytes | None = None) -> str:
    KEYS_PRIVATE_DIR.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()

    encryption = BestAvailableEncryption(password) if password else NoEncryption()
    private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
    PRIVATE_KEY_PATH.write_bytes(private_pem)

    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return public_raw.hex()
