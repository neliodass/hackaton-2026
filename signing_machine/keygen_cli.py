import getpass
from pathlib import Path

from crypto.keygen import PRIVATE_KEY_PATH, generate_keys
from crypto.pq_signer import PQ_SCHEME_LABEL, PQ_SECRET_KEY_PATH, generate_pq_keys

_PACKAGES = Path(__file__).resolve().parent.parent / "server" / "packages"
MANIFEST_SIG_PATH = _PACKAGES / "manifest.sig"
MANIFEST_PQ_SIG_PATH = _PACKAGES / "manifest.pq.sig"


def run_keygen() -> None:
    keys_exist = PRIVATE_KEY_PATH.exists() or PQ_SECRET_KEY_PATH.exists()
    if keys_exist:
        confirm = input("One or more keys already exist. Regenerate both? [y/N]: ")
        if confirm.strip().lower() != "y":
            print("Aborted.")
            return

    raw = getpass.getpass("Ed25519 private key password (leave empty for no encryption): ")
    password = raw.encode() if raw else None

    ed_hex = generate_keys(password)
    pq_hex = generate_pq_keys()

    for sig_path in (MANIFEST_SIG_PATH, MANIFEST_PQ_SIG_PATH):
        if sig_path.exists():
            sig_path.unlink()
            print(f"Removed stale signature: {sig_path}")

    print(f"\nEd25519 private key (PEM): {PRIVATE_KEY_PATH}")
    print(f"{PQ_SCHEME_LABEL} private key (binary): {PQ_SECRET_KEY_PATH}")
    print(f"\nPaste into client/src/config.py:")
    print(f"\n  EMBEDDED_PUBLIC_KEY = \"{ed_hex}\"")
    print(f"\n  EMBEDDED_PQ_PUBLIC_KEY_HEX = \"{pq_hex}\"")
