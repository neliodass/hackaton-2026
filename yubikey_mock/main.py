"""
YubiKey Mock – CLI entry point.

Usage:
    python -m yubikey_mock <command> [--pin-file FILE]

Commands:
    keygen   Generate root keypair  (run once, offline/secure machine)
    certify  Weekly signing ceremony – authorise the signing machine for 7 days
    info     Show current state of root keys and signing certificate
    verify   Verify current signing certificate against root public keys

Options:
    --pin-file FILE   Read YubiKey PIN from a file (UTF-8, single line).
                      If omitted, you will be prompted interactively.

Typical workflow:
    1. python -m yubikey_mock keygen
       (generates root keys, keep the PIN safe)

    2. python signing_machine/main.py keygen
       (generates signing-machine keys)

    3. python -m yubikey_mock certify
       (root key signs a 7-day certificate for the signing machine)

    4. python signing_machine/main.py   (start signing service)
    5. python server/src/main.py        (start update server)
"""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

from .mock_yubikey import MockYubiKey
from .signing_cert import (
    SIGNING_CERT_PATH,
    build_cert_body,
    is_cert_valid,
    load_cert,
    save_cert,
    sign_cert,
    verify_cert,
)

_BASE = Path(__file__).resolve().parent.parent

# Signing-machine key paths (must match signing_machine/keygen_cli.py)
_SIGNING_ED_PRIV = _BASE / "keys" / "private" / "ed25519_signing_sk.pem"
_SIGNING_PQ_PUB  = _BASE / "keys" / "private" / "ml_dsa_65_pk.hex"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_pin(pin_file: Path | None) -> bytes | None:
    if pin_file:
        data = pin_file.read_bytes().strip()
        return data if data else None
    raw = getpass.getpass("YubiKey PIN (leave empty for no PIN): ")
    return raw.encode() if raw else None


def _derive_signing_pubkeys() -> tuple[str, str]:
    """Read signing-machine public keys for embedding in the cert."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, load_pem_private_key,
    )

    if not _SIGNING_ED_PRIV.exists():
        raise FileNotFoundError(
            f"Signing Ed25519 key not found: {_SIGNING_ED_PRIV}\n"
            "Run:  python signing_machine/main.py keygen"
        )
    if not _SIGNING_PQ_PUB.exists():
        raise FileNotFoundError(
            f"Signing ML-DSA public key not found: {_SIGNING_PQ_PUB}\n"
            "Run:  python signing_machine/main.py keygen"
        )

    env_pw = os.environ.get("SIGNING_KEY_PASSWORD", "")
    pw = env_pw.encode() if env_pw else None
    if pw is None:
        raw = getpass.getpass(
            "Signing machine Ed25519 key password (ENTER if none): "
        )
        pw = raw.encode() if raw else None

    ed_priv   = load_pem_private_key(_SIGNING_ED_PRIV.read_bytes(), password=pw)
    ed_pub_hex = ed_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    pq_pub_hex = _SIGNING_PQ_PUB.read_text().strip()

    return ed_pub_hex, pq_pub_hex


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_keygen(pin_file: Path | None) -> None:
    if MockYubiKey.is_ready():
        answer = input("Root keys already exist. Regenerate? [y/N]: ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return

    print("\n[YubiKey MOCK] Generating root keypair ...")
    pin = _read_pin(pin_file)
    ed_pub, pq_pub = MockYubiKey.generate(pin)

    print("\nRoot keys generated and saved to keys/root/")
    print(f"  Ed25519 pub  : {ed_pub}")
    print(f"  {MockYubiKey.pq_label()} pub : {pq_pub[:32]}...{pq_pub[-16:]}")
    print("\nKeep your PIN safe – required for every signing ceremony.")


def cmd_certify(pin_file: Path | None) -> None:
    print("\n" + "=" * 54)
    print("  SIGNING CEREMONY")
    print("  Authorises the signing machine for the next 7 days.")
    print("=" * 54)

    pin = _read_pin(pin_file)
    try:
        yubikey = MockYubiKey(pin)
    except Exception as exc:
        print(f"[ERROR] Could not load YubiKey: {exc}")
        sys.exit(1)

    try:
        ed_pub, pq_pub = _derive_signing_pubkeys()
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)

    print(f"\nSigning machine Ed25519 pub : {ed_pub[:16]}...{ed_pub[-8:]}")

    cert_body = build_cert_body(ed_pub, pq_pub)
    cert      = sign_cert(cert_body, yubikey)
    save_cert(cert)

    print(f"Signing certificate saved: {SIGNING_CERT_PATH}")
    print(f"Valid: {cert['valid_from']}  -->  {cert['valid_to']}")


def cmd_info() -> None:
    print("\n=== YubiKey Mock – Status ===")
    ready = MockYubiKey.is_ready()
    print(f"Root keys initialised : {ready}")
    if ready:
        ed_pub, pq_pub = MockYubiKey.public_keys()
        print(f"Root Ed25519 pub      : {ed_pub[:16]}...{ed_pub[-8:]}")
        print(f"Root {MockYubiKey.pq_label()} pub : {pq_pub[:16]}...{pq_pub[-8:]}")

    cert = load_cert()
    print(f"\nSigning cert present  : {cert is not None}")
    if cert:
        valid = is_cert_valid(cert)
        print(f"  valid_from : {cert.get('valid_from')}")
        print(f"  valid_to   : {cert.get('valid_to')}")
        print(f"  status     : {'VALID' if valid else 'EXPIRED / NOT YET VALID'}")
        print(f"  subject    : {cert.get('subject')}")


def cmd_verify() -> None:
    cert = load_cert()
    if cert is None:
        print("[ERROR] No signing_cert.json found. Run: python -m yubikey_mock certify")
        sys.exit(1)
    if not MockYubiKey.is_ready():
        print("[ERROR] Root keys not found. Run: python -m yubikey_mock keygen")
        sys.exit(1)

    ed_pub, pq_pub = MockYubiKey.public_keys()
    sigs_ok = verify_cert(cert, ed_pub, pq_pub)
    time_ok = is_cert_valid(cert)

    print("\n=== Certificate Verification ===")
    print(f"Root signatures : {'OK' if sigs_ok else 'INVALID'}")
    print(f"Validity period : {'OK' if time_ok else 'EXPIRED'}")
    print(f"Result          : {'PASS' if sigs_ok and time_ok else 'FAIL'}")

    if not (sigs_ok and time_ok):
        sys.exit(1)


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

_MENU = """
╔══════════════════════════════════════╗
║         YubiKey Mock – Menu          ║
╠══════════════════════════════════════╣
║  1  Keygen   – generate root keys    ║
║  2  Certify  – signing ceremony      ║
║  3  Info     – show current status   ║
║  4  Verify   – verify signing cert   ║
║  0  Exit                             ║
╚══════════════════════════════════════╝
"""

_ACTIONS = {
    "1": ("Keygen",  lambda pin_file: cmd_keygen(pin_file)),
    "2": ("Certify", lambda pin_file: cmd_certify(pin_file)),
    "3": ("Info",    lambda _: cmd_info()),
    "4": ("Verify",  lambda _: cmd_verify()),
}


def _pick_pin_file() -> Path | None:
    raw = input("PIN file path (leave empty to type PIN interactively): ").strip()
    if not raw:
        return None
    p = Path(raw)
    if not p.exists():
        print(f"[ERROR] File not found: {p}")
        return None
    return p


def interactive_menu() -> None:
    print(_MENU)
    while True:
        try:
            choice = input("Select option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break

        if choice == "0":
            print("Bye.")
            break

        if choice not in _ACTIONS:
            print(f"  Unknown option: {choice!r}")
            continue

        name, action = _ACTIONS[choice]
        print(f"\n--- {name} ---")
        pin_file = _pick_pin_file() if choice in ("1", "2") else None
        try:
            action(pin_file)
        except SystemExit:
            pass
        print()
        input("Press ENTER to return to menu...")
        print(_MENU)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]

    # No args → interactive menu
    if not args or args[0] in ("-h", "--help", "menu"):
        interactive_menu()
        return

    cmd = args[0]

    pin_file: Path | None = None
    if "--pin-file" in args:
        idx = args.index("--pin-file")
        try:
            pin_file = Path(args[idx + 1])
        except IndexError:
            print("[ERROR] --pin-file requires a path argument.")
            sys.exit(1)
        if not pin_file.exists():
            print(f"[ERROR] PIN file not found: {pin_file}")
            sys.exit(1)

    dispatch = {
        "keygen":  lambda: cmd_keygen(pin_file),
        "certify": lambda: cmd_certify(pin_file),
        "info":    cmd_info,
        "verify":  cmd_verify,
    }

    if cmd not in dispatch:
        print(f"[ERROR] Unknown command: {cmd!r}")
        sys.exit(1)

    dispatch[cmd]()


if __name__ == "__main__":
    main()
