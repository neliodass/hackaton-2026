import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

from crypto.keygen import PRIVATE_KEY_PATH
from crypto.pq_signer import PQ_SECRET_KEY_PATH, sign_pq
from crypto.signer import canonical_manifest_bytes_from_dict, load_private_key

logger = logging.getLogger("signing-machine")

app = FastAPI(title="Signing Machine", version="0.2.0")

_SIGNING_CERT_PATH = Path(__file__).resolve().parent.parent / "keys" / "signing_cert.json"


@app.post("/sign")
async def sign(request: Request) -> Response:
    if not PRIVATE_KEY_PATH.exists():
        raise HTTPException(status_code=503, detail="Private key not found")
    try:
        private_key = load_private_key()
    except Exception as exc:
        logger.error("Failed to load Ed25519 private key: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to load private key: {exc}")

    manifest = await request.json()
    data = canonical_manifest_bytes_from_dict(manifest)
    signature = private_key.sign(data)
    logger.info("Manifest signed (Ed25519)")
    return Response(content=signature, media_type="application/octet-stream")


@app.post("/sign-pq")
async def sign_pq_endpoint(request: Request) -> Response:
    if not PQ_SECRET_KEY_PATH.exists():
        raise HTTPException(status_code=503, detail="PQ secret key not found")
    try:
        manifest = await request.json()
        data = canonical_manifest_bytes_from_dict(manifest)
        signature = sign_pq(data)
    except Exception as exc:
        logger.error("ML-DSA-65 signing failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"PQ signing failed: {exc}")

    logger.info("Manifest signed (ML-DSA-65)")
    return Response(content=signature, media_type="application/octet-stream")


@app.get("/signing-cert")
async def get_signing_cert() -> Response:
    if not _SIGNING_CERT_PATH.exists():
        raise HTTPException(
            status_code=503,
            detail="Signing certificate not found. Run: python -m yubikey_mock certify",
        )
    return Response(
        content=_SIGNING_CERT_PATH.read_bytes(),
        media_type="application/json",
    )


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "key_loaded": PRIVATE_KEY_PATH.exists(),
        "pq_key_loaded": PQ_SECRET_KEY_PATH.exists(),
        "cert_loaded": _SIGNING_CERT_PATH.exists(),
    }
