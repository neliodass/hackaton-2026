from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from dilithium_py.ml_dsa import ML_DSA_65

PQ_SCHEME: Final = ML_DSA_65
PQ_SCHEME_LABEL: Final = "ML-DSA-65"

DEFAULT_PQ_SECRET_PATH = Path(__file__).resolve().parent / "keys" / "private" / "ml_dsa_65_sk.bin"


def canonical_manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
