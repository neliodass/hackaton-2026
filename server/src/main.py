import logging
import sys
import uvicorn

from app import app
from config import HOST, PORT, TLS_CERT_PATH, TLS_KEY_PATH
from manifest import request_signature_from_signing_machine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | update-server | %(message)s",
)

logger = logging.getLogger("update-server")


def _require_tls_files() -> None:
    if TLS_CERT_PATH.is_file() and TLS_KEY_PATH.is_file():
        return
    banner = (
        "\n"
        "Brak certyfikatów HTTPS!\n"
    )
    print(banner, file=sys.stderr)
    logger.error("Brak certyfikatów.")
    sys.exit(1)


def main() -> None:
    request_signature_from_signing_machine()
    _require_tls_files()
    logger.info("Listening on https://%s:%s (TLS)", HOST, PORT)
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        ssl_certfile=str(TLS_CERT_PATH),
        ssl_keyfile=str(TLS_KEY_PATH),
    )


if __name__ == "__main__":
    main()
