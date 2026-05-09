import logging
from pathlib import Path
from time import perf_counter
from zipfile import ZIP_DEFLATED, ZipFile

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from config import HOST, PORT


BASE_DIR = Path(__file__).resolve().parent.parent
PACKAGE_DIR = BASE_DIR / "packages"
MANIFEST_PATH = PACKAGE_DIR / "manifest.json"
UPDATE_PACKAGE_PATH = PACKAGE_DIR / "update.zip"
RELEASE_NOTES_PATH = PACKAGE_DIR / "release_notes.txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | update-server | %(message)s",
)
logger = logging.getLogger("update-server")

app = FastAPI(title="Secure Software Update Server", version="0.1.0")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = perf_counter()
    logger.info("request_started method=%s path=%s", request.method, request.url.path)
    response = await call_next(request)
    duration_ms = (perf_counter() - start) * 1000
    logger.info(
        "request_finished method=%s path=%s status=%s duration_ms=%.2f",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/manifest")
async def get_manifest():
    if not MANIFEST_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "manifest file not found"})
    return FileResponse(path=MANIFEST_PATH, media_type="application/json")


@app.get("/update.zip")
async def get_update_package():
    if not UPDATE_PACKAGE_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "update package not found"})
    return FileResponse(path=UPDATE_PACKAGE_PATH, media_type="application/zip")


def ensure_update_package_exists() -> None:
    if UPDATE_PACKAGE_PATH.exists() or not RELEASE_NOTES_PATH.exists():
        return

    with ZipFile(UPDATE_PACKAGE_PATH, mode="w", compression=ZIP_DEFLATED) as zip_handle:
        zip_handle.write(RELEASE_NOTES_PATH, arcname=RELEASE_NOTES_PATH.name)
    logger.info("Created default update package at %s", UPDATE_PACKAGE_PATH)


def main() -> None:
    ensure_update_package_exists()
    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    main()
