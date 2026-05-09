from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pq_manifest_crypto import DEFAULT_PQ_SECRET_PATH, PQ_SCHEME, PQ_SCHEME_LABEL


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate ML-DSA keypair for manifest.pq.sig signing")
    parser.add_argument(
        "--secret-out",
        type=Path,
        default=DEFAULT_PQ_SECRET_PATH,
        help="Path for raw secret key bytes (keep out of git)",
    )
    args = parser.parse_args()

    secret_path = args.secret_out.expanduser().resolve()
    pk, sk = PQ_SCHEME.keygen()

    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_bytes(sk)

    print(f"PQ keypair ({PQ_SCHEME_LABEL}, dilithium-py)")
    print(f"  secret: {secret_path} ({len(sk)} bytes)")
    print(f"  public: {len(pk)} bytes hex -> set EMBEDDED_PQ_PUBLIC_KEY_HEX in client/src/config.py to:")
    print(pk.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
