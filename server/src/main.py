import json
import logging
from pathlib import Path
from time import perf_counter
from zipfile import ZIP_DEFLATED, ZipFile

import requests
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from config import HOST, PORT, SIGNING_MACHINE_URL

BASE_DIR = Path(__file__).resolve().parent.parent
PACKAGE_DIR = BASE_DIR / "packages"
MANIFEST_PATH = PACKAGE_DIR / "manifest.json"
MANIFEST_SIG_PATH = PACKAGE_DIR / "manifest.sig"
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


@app.get("/manifest.sig")
async def get_manifest_signature():
    if not MANIFEST_SIG_PATH.exists():
        return JSONResponse(status_code=404, content={"error": "manifest signature not found"})
    return FileResponse(path=MANIFEST_SIG_PATH, media_type="application/octet-stream")


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


def request_signature_from_signing_machine() -> None:
    if not MANIFEST_PATH.exists():
        return
    if (
        MANIFEST_SIG_PATH.exists()
        and MANIFEST_SIG_PATH.stat().st_mtime >= MANIFEST_PATH.stat().st_mtime
    ):
        logger.info("Manifest signature is up to date")
        return

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    try:
        response = requests.post(
            f"{SIGNING_MACHINE_URL}/sign",
            json=manifest,
            timeout=10,
        )
        response.raise_for_status()
    except requests.ConnectionError:
        logger.warning("Signing machine not reachable at %s — running without fresh signature", SIGNING_MACHINE_URL)
        return
    except requests.HTTPError as exc:
        logger.error("Signing machine returned error: %s", exc)
        return
    except requests.Timeout:
        logger.error("Signing machine request timed out")
        return

    MANIFEST_SIG_PATH.write_bytes(response.content)
    logger.info("Manifest signed by signing machine, signature saved to %s", MANIFEST_SIG_PATH)


def main() -> None:
    ensure_update_package_exists()
    request_signature_from_signing_machine()
    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    main()
