"""
Shared pytest fixtures dla testów bezpieczeństwa systemu aktualizacji.

Wszystkie klucze są efemeryczne (generowane in-memory per test).
Żadne pliki na dysku nie są modyfikowane.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Dodaj client/src do sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "client" / "src"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def make_manifest(
    version: str = "2.0.0",
    rid: str = "test-release-001",
    released_at: datetime | None = None,
) -> dict:
    ts = (released_at or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    payload = b"Authentic update payload " + version.encode()
    sha = hashlib.sha256(payload).hexdigest()
    return {
        "id":           rid,
        "version":      version,
        "released_at":  ts,
        "package_name": "update.zip",
        "package_url":  f"https://127.0.0.1:8000/binary/{rid}",
        "sha256":       sha,
        "size_bytes":   len(payload),
        "chunk_size":   1024 * 1024,
        "chunk_hashes": [sha],
    }


def make_cert_body(
    ed_pub: str,
    pq_pub: str,
    valid_from: datetime,
    valid_to: datetime,
) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "issued_at":      now.isoformat(),
        "signing_pubkey": {"ed25519": ed_pub, "mldsa65": pq_pub},
        "subject":        "signing-machine",
        "valid_from":     valid_from.isoformat(),
        "valid_to":       valid_to.isoformat(),
        "version":        1,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def ed25519_keypair():
    """Efemeryczny klucz Ed25519 → (sk, pk_hex)."""
    pytest.importorskip("cryptography", reason="pip install cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw().hex()


@pytest.fixture()
def mldsa65_keypair():
    """Efemeryczny klucz ML-DSA-65 → (pk_bytes, sk_bytes)."""
    ML_DSA_65 = pytest.importorskip("dilithium_py.ml_dsa", reason="pip install dilithium-py").ML_DSA_65
    return ML_DSA_65.keygen()


@pytest.fixture()
def manifest():
    return make_manifest()


@pytest.fixture()
def verifiers():
    """Importuje funkcje weryfikujące z projektu lub skipuje test."""
    mod = pytest.importorskip(
        "crypto.verifier",
        reason="uruchom testy z katalogu projektu lub dodaj client/src do PYTHONPATH",
    )
    return mod


@pytest.fixture()
def merkle_verifier():
    return pytest.importorskip("merkle_verifier", reason="brak merkle_verifier w PYTHONPATH")


@pytest.fixture()
def valid_cert_body():
    """Ciało certyfikatu z aktualnym oknem czasowym."""
    now = datetime.now(timezone.utc)
    return make_cert_body(
        "aa" * 32, "bb" * 100,
        valid_from=now.replace(hour=0, minute=0, second=0, microsecond=0),
        valid_to=now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=7),
    )
