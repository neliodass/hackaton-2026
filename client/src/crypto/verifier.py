from __future__ import annotations

import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dilithium_py.ml_dsa import ML_DSA_65

try:
    from dilithium_py.ml_dsa import ML_DSA_87 as _PQ_ROOT_SCHEME
except ImportError:
    from dilithium_py.ml_dsa import ML_DSA_65 as _PQ_ROOT_SCHEME  # type: ignore[assignment]


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Manifest verification (against signing-machine keys, extracted from cert)
# ---------------------------------------------------------------------------

def verify_manifest_signature(manifest: dict, signature: bytes, hex_public_key: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_public_key))
        pub.verify(signature, _canonical(manifest))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_manifest_pq_signature(manifest: dict, signature: bytes, public_key_hex: str) -> bool:
    try:
        pk = bytes.fromhex(public_key_hex.strip())
    except ValueError:
        return False
    return bool(ML_DSA_65.verify(pk, _canonical(manifest), signature, ctx=b""))


# ---------------------------------------------------------------------------
# Signing certificate verification (against ROOT keys embedded in client)
# ---------------------------------------------------------------------------

def verify_signing_cert(cert: dict, root_ed_pub_hex: str, root_pq_pub_hex: str) -> bool:
    """Verify Ed25519 + ML-DSA root signatures over the signing certificate body."""
    sigs = cert.get("root_signatures", {})
    body = {k: v for k, v in cert.items() if k != "root_signatures"}
    data = _canonical(body)

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(root_ed_pub_hex))
        pub.verify(bytes.fromhex(sigs["ed25519"]), data)
    except (InvalidSignature, KeyError, ValueError):
        return False

    try:
        ok = _PQ_ROOT_SCHEME.verify(
            bytes.fromhex(root_pq_pub_hex),
            data,
            bytes.fromhex(sigs["mldsa"]),
            ctx=b"",
        )
        if not ok:
            return False
    except (KeyError, ValueError):
        return False

    return True


def is_cert_time_valid(cert: dict) -> bool:
    """Return True if current time is within the cert's validity window."""
    try:
        now = datetime.now(timezone.utc)
        return (
            datetime.fromisoformat(cert["valid_from"]) <= now <=
            datetime.fromisoformat(cert["valid_to"])
        )
    except (KeyError, ValueError):
        return False
