import json

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse

from config import (
    LATEST_POINTER_PATH,
    MANIFEST_PATH,
    MANIFEST_PQ_SIG_PATH,
    MANIFEST_SIG_PATH,
    SIGNING_CERT_PATH,
    UPDATE_PACKAGE_PATH,
    VERSIONS_DIR,
)

router = APIRouter()


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/manifest")
async def get_manifest():
    if not MANIFEST_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "manifest file not found"})
    return FileResponse(path=MANIFEST_PATH, media_type="application/json")


@router.get("/manifest.sig")
async def get_manifest_signature():
    if not MANIFEST_SIG_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "manifest signature not found"})
    return FileResponse(path=MANIFEST_SIG_PATH, media_type="application/octet-stream")


@router.get("/manifest.pq.sig")
async def get_manifest_signature_pq():
    if not MANIFEST_PQ_SIG_PATH.exists():
        return JSONResponse(
            status_code=404,
            content={"error": "hybrid ML-DSA manifest signature (manifest.pq.sig) not found"},
        )
    return FileResponse(path=MANIFEST_PQ_SIG_PATH, media_type="application/octet-stream")


@router.get("/signing-cert")
async def get_signing_cert():
    if not SIGNING_CERT_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "signing certificate not found"})
    return FileResponse(path=SIGNING_CERT_PATH, media_type="application/json")


@router.get("/update.zip")
async def get_update_package():
    if not UPDATE_PACKAGE_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "update package not found"})
    return FileResponse(path=UPDATE_PACKAGE_PATH, media_type="application/zip")


# ── Versioned release endpoints ──────────────────────────────────────────────

@router.get("/latest")
async def get_latest():
    if not LATEST_POINTER_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "no releases available yet"})
    pointer = json.loads(LATEST_POINTER_PATH.read_text(encoding="utf-8"))
    release_id = pointer.get("id")
    manifest_path = VERSIONS_DIR / release_id / "manifest.json"
    if not manifest_path.exists():
        return JSONResponse(status_code=404, content={"error": "latest manifest not found"})
    return FileResponse(path=manifest_path, media_type="application/json")


@router.get("/binary/{release_id}")
async def get_binary(release_id: str):
    path = VERSIONS_DIR / release_id / "update.txt"
    if not path.exists():
        return JSONResponse(status_code=404, content={"error": "binary not found"})
    return FileResponse(path=path, media_type="application/octet-stream")


@router.get("/sig/{release_id}")
async def get_sig(release_id: str):
    path = VERSIONS_DIR / release_id / "manifest.sig"
    if not path.exists():
        return JSONResponse(status_code=404, content={"error": "signature not found"})
    return FileResponse(path=path, media_type="application/octet-stream")


@router.get("/sig-pq/{release_id}")
async def get_sig_pq(release_id: str):
    path = VERSIONS_DIR / release_id / "manifest.pq.sig"
    if not path.exists():
        return JSONResponse(status_code=404, content={"error": "PQ signature not found"})
    return FileResponse(path=path, media_type="application/octet-stream")


@router.get("/cert/{release_id}")
async def get_cert(release_id: str):
    path = VERSIONS_DIR / release_id / "signing_cert.json"
    if not path.exists():
        return JSONResponse(status_code=404, content={"error": "signing cert not found"})
    return FileResponse(path=path, media_type="application/json")
