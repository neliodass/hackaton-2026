import logging
import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "server" / "src"))

import uvicorn

from app import app
from keygen_cli import run_keygen

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | signing-machine | %(message)s",
)

HOST = os.environ.get("SIGNING_MACHINE_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIGNING_MACHINE_PORT", "9000"))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "keygen":
        run_keygen()
    else:
        uvicorn.run(app, host=HOST, port=PORT)
