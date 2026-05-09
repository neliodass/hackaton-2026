import logging

import uvicorn

from app import app
from config import HOST, PORT
from manifest import request_signature_from_signing_machine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | update-server | %(message)s",
)


def main() -> None:
    request_signature_from_signing_machine()
    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    main()
