import getpass
from pathlib import Path

from crypto.keygen import PRIVATE_KEY_PATH, generate_keys

MANIFEST_SIG_PATH = Path(__file__).resolve().parent.parent / "server" / "packages" / "manifest.sig"


def run_keygen() -> None:
    if PRIVATE_KEY_PATH.exists():
        confirm = input(f"A key already exists at {PRIVATE_KEY_PATH}. Overwrite? [y/N]: ")
        if confirm.strip().lower() != "y":
            print("Aborted.")
            return
    raw = getpass.getpass("Private key password (leave empty for no encryption): ")
    password = raw.encode() if raw else None
    hex_key = generate_keys(password)

    if MANIFEST_SIG_PATH.exists():
        MANIFEST_SIG_PATH.unlink()
        print(f"Removed stale signature: {MANIFEST_SIG_PATH}")

    print(f"\nPrivate key (Ed25519 PEM): {PRIVATE_KEY_PATH}")
    print(f"\nPaste this into client/src/config.py as EMBEDDED_PUBLIC_KEY:\n\n{hex_key}\n")
