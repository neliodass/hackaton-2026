import json
from pathlib import Path

import requests as _requests
from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse

from config import (
    LATEST_POINTER_PATH,
    MANIFEST_PATH,
    MANIFEST_PQ_SIG_PATH,
    MANIFEST_SIG_PATH,
    MERKLE_SERVICE_URL,
    SIGNING_CERT_PATH,
    UPDATE_PACKAGE_PATH,
    VERSIONS_DIR,
)

router = APIRouter()

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ROOT_ED_PUB = _PROJECT_ROOT / "keys" / "root" / "root_ed25519_pub.hex"
_ROOT_MLDSA_PUB = _PROJECT_ROOT / "keys" / "root" / "root_mldsa_pub.hex"


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
    version_dir = VERSIONS_DIR / release_id
    manifest_path = version_dir / "manifest.json"
    if manifest_path.exists():
        try:
            pkg_name = json.loads(manifest_path.read_text(encoding="utf-8")).get("package_name", "update.txt")
            path = version_dir / pkg_name
        except (json.JSONDecodeError, OSError):
            path = version_dir / "update.txt"
    else:
        path = version_dir / "update.txt"
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
    if path.exists():
        return FileResponse(path=path, media_type="application/json")
    # Fall back to the global cert fetched by the server at startup
    if SIGNING_CERT_PATH.exists():
        return FileResponse(path=SIGNING_CERT_PATH, media_type="application/json")
    return JSONResponse(status_code=404, content={"error": "signing cert not found"})


# ── Root public keys ──────────────────────────────────────────────────────────

@router.get("/keys")
async def get_keys():
    ed_hex = _ROOT_ED_PUB.read_text().strip() if _ROOT_ED_PUB.exists() else ""
    mldsa_hex = _ROOT_MLDSA_PUB.read_text().strip() if _ROOT_MLDSA_PUB.exists() else ""
    return {"root_ed25519": ed_hex, "root_mldsa65": mldsa_hex}


# ── Merkle transparency log proxy ─────────────────────────────────────────────

@router.get("/log")
async def proxy_log():
    try:
        r = _requests.get(MERKLE_SERVICE_URL + "/log", timeout=10)
        r.raise_for_status()
        return JSONResponse(content=r.json())
    except Exception as exc:
        return JSONResponse(status_code=503, content={"error": f"Merkle service unavailable: {exc}"})


@router.get("/proof/{release_id}")
async def proxy_proof(release_id: str):
    try:
        r = _requests.get(f"{MERKLE_SERVICE_URL}/proof/{release_id}", timeout=10)
        return JSONResponse(content=r.json(), status_code=r.status_code)
    except Exception as exc:
        return JSONResponse(status_code=503, content={"error": f"Merkle service unavailable: {exc}"})


@router.get("/merkle-tree")
async def proxy_merkle_tree():
    try:
        r = _requests.get(MERKLE_SERVICE_URL + "/merkle-tree", timeout=10)
        r.raise_for_status()
        return JSONResponse(content=r.json())
    except Exception as exc:
        return JSONResponse(status_code=503, content={"error": f"Merkle service unavailable: {exc}"})
