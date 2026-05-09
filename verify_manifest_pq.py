from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pq_manifest_crypto import PQ_SCHEME, canonical_manifest_bytes


DEFAULT_MANIFEST = Path(__file__).resolve().parent / "server" / "packages" / "manifest.json"
DEFAULT_SIGNATURE = Path(__file__).resolve().parent / "server" / "packages" / "manifest.pq.sig"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify hybrid ML-DSA manifest.pq.sig")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sig", type=Path, default=DEFAULT_SIGNATURE)
    parser.add_argument(
        "--public-key-hex",
        required=True,
        help="Embedded ML-DSA public key bytes as hex string (matches generate_pq_keys output)",
    )
    args = parser.parse_args()

    manifest_path = args.manifest.expanduser().resolve()
    sig_path = args.sig.expanduser().resolve()

    if not manifest_path.exists():
        print("FAILURE: manifest file missing")
        return 1
    if not sig_path.exists():
        print("FAILURE: PQ signature file missing")
        return 1

    try:
        pk = bytes.fromhex(args.public_key_hex.strip())
    except ValueError:
        print("FAILURE: invalid --public-key-hex (not hex)")
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    body = canonical_manifest_bytes(manifest)
    sig = sig_path.read_bytes()

    ok = PQ_SCHEME.verify(pk, body, sig, ctx=b"")
    if ok:
        print("SUCCESS: hybrid ML-DSA manifest.pq.sig verifies")
        return 0

    print("FAILURE: ML-DSA PQ signature INVALID or malformed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
