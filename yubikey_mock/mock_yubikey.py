from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

try:
    from dilithium_py.ml_dsa import ML_DSA_87 as PQ_ROOT_SCHEME
    PQ_ROOT_LABEL = "ML-DSA-87"
except ImportError:
    from dilithium_py.ml_dsa import ML_DSA_65 as PQ_ROOT_SCHEME  # type: ignore[assignment]
    PQ_ROOT_LABEL = "ML-DSA-65"

_KEYS_ROOT = Path(__file__).resolve().parent.parent / "keys" / "root"

ED_KEY_PATH = _KEYS_ROOT / "root_ed25519.pem"
PQ_KEY_PATH = _KEYS_ROOT / "root_mldsa.bin"
ED_PUB_PATH = _KEYS_ROOT / "root_ed25519_pub.hex"
PQ_PUB_PATH = _KEYS_ROOT / "root_mldsa_pub.hex"


class MockYubiKey:
    """
    Simulates a YubiKey hardware security token.

    Root keys live in password-protected files instead of real hardware.
    Physical touch is replaced by an interactive console confirmation.
    """

    def __init__(self, pin: bytes | None = None):
        if not ED_KEY_PATH.exists() or not PQ_KEY_PATH.exists():
            raise FileNotFoundError(
                "Root keys not found. Run: python -m yubikey_mock keygen"
            )
        self._ed_key = load_pem_private_key(ED_KEY_PATH.read_bytes(), password=pin)
        self._pq_sk  = PQ_KEY_PATH.read_bytes()

    def touch_and_sign(self, data: bytes) -> tuple[bytes, bytes]:
        """
        Simulate physical touch + sign with both root keys.
        Returns (ed25519_signature, mldsa_signature).
        """
        print()
        print("=" * 54)
        print("  [YubiKey MOCK]  Signing request received")
        print(f"  Algorithm : Ed25519 + {PQ_ROOT_LABEL} (hybrid)")
        print(f"  Data size : {len(data)} bytes")
        print("=" * 54)
        input("  >>> Touch YubiKey [press ENTER to simulate]: ")

        ed_sig = self._ed_key.sign(data)
        pq_sig = PQ_ROOT_SCHEME.sign(self._pq_sk, data, ctx=b"", deterministic=True)

        print("  [OK] Signed successfully.")
        print("=" * 54)
        print()
        return ed_sig, pq_sig

    @classmethod
    def generate(cls, pin: bytes | None) -> tuple[str, str]:
        """
        Generate a new root keypair and persist to keys/root/.
        Returns (ed25519_pub_hex, mldsa_pub_hex).
        PIN protects the Ed25519 private key file (PEM encryption).
        """
        _KEYS_ROOT.mkdir(parents=True, exist_ok=True)

        ed_priv = Ed25519PrivateKey.generate()
        encryption = BestAvailableEncryption(pin) if pin else NoEncryption()
        ED_KEY_PATH.write_bytes(
            ed_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
        )
        ed_pub_hex = ed_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        ED_PUB_PATH.write_text(ed_pub_hex)

        pq_pk, pq_sk = PQ_ROOT_SCHEME.keygen()
        PQ_KEY_PATH.write_bytes(pq_sk)
        pq_pub_hex = pq_pk.hex()
        PQ_PUB_PATH.write_text(pq_pub_hex)

        return ed_pub_hex, pq_pub_hex

    @staticmethod
    def public_keys() -> tuple[str, str]:
        """Returns (ed25519_pub_hex, mldsa_pub_hex) of root keys."""
        return ED_PUB_PATH.read_text().strip(), PQ_PUB_PATH.read_text().strip()

    @staticmethod
    def is_ready() -> bool:
        return ED_KEY_PATH.exists() and PQ_KEY_PATH.exists()

    @staticmethod
    def pq_label() -> str:
        return PQ_ROOT_LABEL
