import hashlib
import json
import logging

import requests

from config import (
    MANIFEST_PATH,
    MANIFEST_PQ_SIG_PATH,
    MANIFEST_SIG_PATH,
    SIGNING_CERT_PATH,
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


def _request_signature(endpoint: str, sig_path, manifest: dict, label: str) -> None:
    try:
        response = requests.post(
            f"{SIGNING_MACHINE_URL}{endpoint}",
            json=manifest,
            timeout=10,
        )
        response.raise_for_status()
    except requests.ConnectionError:
        logger.warning(
            "Signing machine not reachable at %s — running without fresh %s signature",
            SIGNING_MACHINE_URL,
            label,
        )
        return
    except requests.HTTPError as exc:
        logger.error("Signing machine returned error for %s: %s", label, exc)
        return
    except requests.Timeout:
        logger.error("Signing machine request timed out for %s", label)
        return

    sig_path.write_bytes(response.content)
    logger.info("%s manifest signed, signature saved to %s", label, sig_path)


def _fetch_signing_cert() -> None:
    try:
        response = requests.get(f"{SIGNING_MACHINE_URL}/signing-cert", timeout=10)
        response.raise_for_status()
    except requests.ConnectionError:
        logger.warning("Signing machine not reachable — signing cert not fetched")
        return
    except (requests.HTTPError, requests.Timeout) as exc:
        logger.error("Failed to fetch signing cert: %s", exc)
        return
    SIGNING_CERT_PATH.write_text(response.text, encoding="utf-8")
    logger.info("Signing certificate saved to %s", SIGNING_CERT_PATH)


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

    manifest_mtime = MANIFEST_PATH.stat().st_mtime

    if not (MANIFEST_SIG_PATH.exists() and MANIFEST_SIG_PATH.stat().st_mtime >= manifest_mtime):
        _request_signature("/sign", MANIFEST_SIG_PATH, manifest, "Ed25519")
    else:
        logger.info("Ed25519 manifest signature is up to date")

    if not (MANIFEST_PQ_SIG_PATH.exists() and MANIFEST_PQ_SIG_PATH.stat().st_mtime >= manifest_mtime):
        _request_signature("/sign-pq", MANIFEST_PQ_SIG_PATH, manifest, "ML-DSA-65")
    else:
        logger.info("ML-DSA-65 manifest signature is up to date")

    _fetch_signing_cert()
