import json

from cryptography.exceptions import InvalidSignature
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def load_public_key(hex_key: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))


def canonical_manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def verify_manifest_signature(manifest: dict, signature: bytes, hex_public_key: str) -> bool:
    public_key = load_public_key(hex_public_key)
    data = canonical_manifest_bytes(manifest)
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def verify_manifest_pq_signature(manifest: dict, signature: bytes, public_key_hex: str) -> bool:
    try:
        pk = bytes.fromhex(public_key_hex.strip())
    except ValueError:
        return False
    data = canonical_manifest_bytes(manifest)
    return bool(ML_DSA_65.verify(pk, data, signature, ctx=b""))
