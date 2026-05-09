import getpass
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "src"))

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

from crypto.keygen import PRIVATE_KEY_PATH, generate_keys
from crypto.signer import canonical_manifest_bytes_from_dict, load_private_key

MANIFEST_SIG_PATH = Path(__file__).resolve().parent.parent / "server" / "packages" / "manifest.sig"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | signing-machine | %(message)s",
)
logger = logging.getLogger("signing-machine")

HOST = os.environ.get("SIGNING_MACHINE_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIGNING_MACHINE_PORT", "9000"))

app = FastAPI(title="Signing Machine", version="0.1.0")


@app.post("/sign")
async def sign(request: Request) -> Response:
    if not PRIVATE_KEY_PATH.exists():
        raise HTTPException(status_code=503, detail="Private key not found")
    try:
        private_key = load_private_key()
    except Exception as exc:
        logger.error("Failed to load private key: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to load private key: {exc}")

    manifest = await request.json()
    data = canonical_manifest_bytes_from_dict(manifest)
    signature = private_key.sign(data)
    logger.info("Manifest signed successfully")
    return Response(content=signature, media_type="application/octet-stream")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "key_loaded": PRIVATE_KEY_PATH.exists()}


def run_keygen() -> None:
    if PRIVATE_KEY_PATH.exists():
        confirm = input(f"Key already exists at {PRIVATE_KEY_PATH}. Overwrite? [y/N]: ")
        if confirm.strip().lower() != "y":
            print("Aborted.")
            return
    raw = getpass.getpass("Private key password (leave empty for no encryption): ")
    password = raw.encode() if raw else None
    hex_key = generate_keys(password)

    old_sig = MANIFEST_SIG_PATH
    if old_sig.exists():
        old_sig.unlink()
        print(f"Removed stale signature: {old_sig}")

    print(f"\nPrivate key: {PRIVATE_KEY_PATH}")
    print(f"\nPaste this into client/src/config.py as EMBEDDED_PUBLIC_KEY:\n\n{hex_key}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "keygen":
        run_keygen()
    else:
        uvicorn.run(app, host=HOST, port=PORT)
