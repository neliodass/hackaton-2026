import hashlib
import json
import logging

import requests

from config import (
    MANIFEST_PATH,
    MANIFEST_SIG_PATH,
    SIGNING_MACHINE_URL,
    UPDATE_PACKAGE_PATH,
)

CHUNK_SIZE = 1024 * 1024

logger = logging.getLogger("update-server")


def compute_package_hashes() -> dict:
    full_hasher = hashlib.sha256()
    chunk_hashes = []
    with UPDATE_PACKAGE_PATH.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            full_hasher.update(chunk)
            chunk_hashes.append(hashlib.sha256(chunk).hexdigest())
    return {
        "sha256": full_hasher.hexdigest(),
        "size_bytes": UPDATE_PACKAGE_PATH.stat().st_size,
        "chunk_size": CHUNK_SIZE,
        "chunk_hashes": chunk_hashes,
    }


def request_signature_from_signing_machine() -> None:
    if not MANIFEST_PATH.exists():
        return

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    if UPDATE_PACKAGE_PATH.exists():
        hashes = compute_package_hashes()
        if any(manifest.get(k) != v for k, v in hashes.items()):
            manifest.update(hashes)
            MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            logger.info(
                "Updated manifest: sha256=%s size_bytes=%d chunks=%d",
                hashes["sha256"],
                hashes["size_bytes"],
                len(hashes["chunk_hashes"]),
            )
    else:
        logger.warning("update.zip not found — sha256/size_bytes not added to manifest")

    if (
        MANIFEST_SIG_PATH.exists()
        and MANIFEST_SIG_PATH.stat().st_mtime >= MANIFEST_PATH.stat().st_mtime
    ):
        logger.info("Manifest signature is up to date")
        return

    try:
        response = requests.post(
            f"{SIGNING_MACHINE_URL}/sign",
            json=manifest,
            timeout=10,
        )
        response.raise_for_status()
    except requests.ConnectionError:
        logger.warning(
            "Signing machine not reachable at %s — running without fresh signature",
            SIGNING_MACHINE_URL,
        )
        return
    except requests.HTTPError as exc:
        logger.error("Signing machine returned error: %s", exc)
        return
    except requests.Timeout:
        logger.error("Signing machine request timed out")
        return

    MANIFEST_SIG_PATH.write_bytes(response.content)
    logger.info("Manifest signed by signing machine, signature saved to %s", MANIFEST_SIG_PATH)
