from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse

from config import MANIFEST_PATH, MANIFEST_SIG_PATH, UPDATE_PACKAGE_PATH

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


@router.get("/update.zip")
async def get_update_package():
    if not UPDATE_PACKAGE_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "update package not found"})
    return FileResponse(path=UPDATE_PACKAGE_PATH, media_type="application/zip")
