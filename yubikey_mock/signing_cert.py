from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .mock_yubikey import PQ_ROOT_SCHEME

SIGNING_CERT_PATH = Path(__file__).resolve().parent.parent / "keys" / "signing_cert.json"
CERT_VALIDITY_DAYS = 7


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def build_cert_body(signing_ed_pub: str, signing_pq_pub: str) -> dict:
    now   = datetime.now(timezone.utc).replace(microsecond=0)
    today = now.replace(hour=0, minute=0, second=0)
    return {
        "issued_at":   now.isoformat(),
        "signing_pubkey": {
            "ed25519": signing_ed_pub,
            "mldsa65": signing_pq_pub,
        },
        "subject":    "signing-machine",
        "valid_from": today.isoformat(),
        "valid_to":   (today + timedelta(days=CERT_VALIDITY_DAYS)).isoformat(),
        "version":    1,
    }


def sign_cert(cert_body: dict, yubikey) -> dict:
    """Sign cert_body with YubiKey root keys. Returns the full signed cert."""
    data = _canonical(cert_body)
    ed_sig, pq_sig = yubikey.touch_and_sign(data)
    return {
        **cert_body,
        "root_signatures": {
            "ed25519": ed_sig.hex(),
            "mldsa":   pq_sig.hex(),
        },
    }


def save_cert(cert: dict) -> None:
    SIGNING_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SIGNING_CERT_PATH.write_text(json.dumps(cert, indent=2, ensure_ascii=True))


def load_cert() -> dict | None:
    if not SIGNING_CERT_PATH.exists():
        return None
    return json.loads(SIGNING_CERT_PATH.read_text())


def verify_cert(cert: dict, root_ed_pub_hex: str, root_pq_pub_hex: str) -> bool:
    """Verify root signatures over the cert body (all fields except root_signatures)."""
    sigs = cert.get("root_signatures", {})
    body = {k: v for k, v in cert.items() if k != "root_signatures"}
    data = _canonical(body)

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(root_ed_pub_hex))
        pub.verify(bytes.fromhex(sigs["ed25519"]), data)
    except (InvalidSignature, KeyError, ValueError):
        return False

    try:
        ok = PQ_ROOT_SCHEME.verify(
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


def is_cert_valid(cert: dict) -> bool:
    try:
        now        = datetime.now(timezone.utc)
        valid_from = datetime.fromisoformat(cert["valid_from"])
        valid_to   = datetime.fromisoformat(cert["valid_to"])
        return valid_from <= now <= valid_to
    except (KeyError, ValueError):
        return False
