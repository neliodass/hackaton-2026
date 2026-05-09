import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

from crypto.keygen import PRIVATE_KEY_PATH
from crypto.signer import canonical_manifest_bytes_from_dict, load_private_key

logger = logging.getLogger("signing-machine")

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
