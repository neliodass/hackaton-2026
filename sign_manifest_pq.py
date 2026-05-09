from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pq_manifest_crypto import (
    DEFAULT_PQ_SECRET_PATH,
    PQ_SCHEME,
    canonical_manifest_bytes,
)


DEFAULT_MANIFEST = Path(__file__).resolve().parent / "server" / "packages" / "manifest.json"
DEFAULT_SIGNATURE_OUT = Path(__file__).resolve().parent / "server" / "packages" / "manifest.pq.sig"


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign manifest.json with ML-DSA (hybrid second slot)")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="manifest.json path")
    parser.add_argument(
        "--secret",
        type=Path,
        default=DEFAULT_PQ_SECRET_PATH,
        help="Raw ML-DSA secret key bytes produced by generate_pq_keys.py",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_SIGNATURE_OUT,
        help="Output signature path (default: manifest.pq.sig next to release pack)",
    )
    args = parser.parse_args()

    manifest_path = args.manifest.expanduser().resolve()
    secret_path = args.secret.expanduser().resolve()

    if not manifest_path.exists():
        print(f"FAILURE: manifest not found: {manifest_path}", file=sys.stderr)
        return 1
    if not secret_path.exists():
        print(f"FAILURE: PQ secret key not found: {secret_path}", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    body = canonical_manifest_bytes(manifest)
    sk = secret_path.read_bytes()
    sig = PQ_SCHEME.sign(sk, body, ctx=b"", deterministic=True)

    out_path = args.out.expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(sig)

    print(f"[hybrid signing] wrote ML-DSA signature ({len(sig)} bytes) -> {out_path}")
    print("Hybrid release: regenerate manifest.sig (Ed25519) via signing machine; both signatures are mandatory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
