from __future__ import annotations

import argparse
import ipaddress
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_CERT = _REPO_ROOT / "certs" / "dev.crt"
_DEFAULT_KEY = _REPO_ROOT / "certs" / "dev.key"


def write_cert_pair(cert_path: Path, key_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    cert = builder.sign(key, hashes.SHA256())

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Self-signed cert for local HTTPS (demo only)")
    parser.add_argument("--cert-out", type=Path, default=_DEFAULT_CERT)
    parser.add_argument("--key-out", type=Path, default=_DEFAULT_KEY)
    args = parser.parse_args()

    write_cert_pair(args.cert_out.expanduser().resolve(), args.key_out.expanduser().resolve())
    print(f"Wrote certificate: {args.cert_out}")
    print(f"Wrote private key: {args.key_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
