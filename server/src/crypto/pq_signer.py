from __future__ import annotations

from pathlib import Path
from typing import Final

from dilithium_py.ml_dsa import ML_DSA_65

_KEYS_ROOT = Path(__file__).resolve().parent.parent.parent.parent / "keys"
PQ_SECRET_KEY_PATH = _KEYS_ROOT / "private" / "ml_dsa_65_sk.bin"
PQ_PUBLIC_KEY_PATH = _KEYS_ROOT / "private" / "ml_dsa_65_pk.hex"

PQ_SCHEME: Final = ML_DSA_65
PQ_SCHEME_LABEL: Final = "ML-DSA-65"


def generate_pq_keys() -> str:
    PQ_SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    pk, sk = PQ_SCHEME.keygen()
    PQ_SECRET_KEY_PATH.write_bytes(sk)
    pk_hex = pk.hex()
    PQ_PUBLIC_KEY_PATH.write_text(pk_hex)
    return pk_hex


def sign_pq(data: bytes) -> bytes:
    sk = PQ_SECRET_KEY_PATH.read_bytes()
    return PQ_SCHEME.sign(sk, data, ctx=b"", deterministic=True)
