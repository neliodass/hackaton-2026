import hashlib
import json
import logging
import random
import string
import uuid
from pathlib import Path

import requests

from config import (
    HOST,
    LATEST_POINTER_PATH,
    MERKLE_SERVICE_URL,
    PORT,
    SIGNING_MACHINE_URL,
    VERSIONS_DIR,
)

CHUNK_SIZE = 1024 * 1024

logger = logging.getLogger("update-server")


def _canonical_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _compute_file_hashes(path: Path) -> dict:
    full_hasher = hashlib.sha256()
    chunk_hashes: list[str] = []
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            full_hasher.update(chunk)
            chunk_hashes.append(hashlib.sha256(chunk).hexdigest())
    return {
        "sha256": full_hasher.hexdigest(),
        "size_bytes": path.stat().st_size,
        "chunk_size": CHUNK_SIZE,
        "chunk_hashes": chunk_hashes,
    }


def _request_sig(endpoint: str, manifest: dict, label: str) -> bytes | None:
    try:
        resp = requests.post(f"{SIGNING_MACHINE_URL}{endpoint}", json=manifest, timeout=15)
        resp.raise_for_status()
        return resp.content
    except requests.ConnectionError:
        logger.warning("Signing machine not reachable (%s) — skipping %s signature", SIGNING_MACHINE_URL, label)
    except requests.HTTPError as exc:
        logger.error("Signing machine error for %s: %s", label, exc)
    except requests.Timeout:
        logger.error("Signing machine timed out for %s", label)
    return None


def _fetch_signing_cert() -> dict | None:
    try:
        resp = requests.get(f"{SIGNING_MACHINE_URL}/signing-cert", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("Could not fetch signing cert: %s", exc)
    return None


def _register_leaf(release_id: str, merkle_hash: str) -> None:
    try:
        resp = requests.post(
            f"{MERKLE_SERVICE_URL}/leaf",
            json={"id": release_id, "hash": merkle_hash},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Merkle leaf registered: id=%s hash=%s...", release_id, merkle_hash[:16])
    except requests.ConnectionError:
        logger.warning("Merkle service not reachable at %s — leaf not registered", MERKLE_SERVICE_URL)
    except Exception as exc:
        logger.error("Failed to register Merkle leaf: %s", exc)


def create_new_release(version: str) -> None:
    release_id = str(uuid.uuid4())
    version_dir = VERSIONS_DIR / release_id
    version_dir.mkdir(parents=True, exist_ok=True)

    # Generate simulated update file
    random_content = "".join(random.choices(string.ascii_letters + string.digits, k=2048))
    file_content = f"Version: {version}\nID: {release_id}\n\n{random_content}\n"
    update_path = version_dir / "update.txt"
    update_path.write_text(file_content, encoding="utf-8")
    logger.info("Generated update.txt (%d bytes)", len(file_content))

    # Compute hashes
    hashes = _compute_file_hashes(update_path)

    # Build manifest (no sig fields yet)
    manifest: dict = {
        "id": release_id,
        "version": version,
        "package_name": "update.txt",
        "package_url": f"http://{HOST}:{PORT}/binary/{release_id}",
        **hashes,
    }

    # Sign with signing machine
    ed_sig = _request_sig("/sign", manifest, "Ed25519")
    pq_sig = _request_sig("/sign-pq", manifest, "ML-DSA-65")

    if ed_sig:
        (version_dir / "manifest.sig").write_bytes(ed_sig)
        logger.info("Ed25519 signature saved")
    else:
        logger.warning("Release created WITHOUT Ed25519 signature")

    if pq_sig:
        (version_dir / "manifest.pq.sig").write_bytes(pq_sig)
        logger.info("ML-DSA-65 signature saved")
    else:
        logger.warning("Release created WITHOUT ML-DSA-65 signature")

    # Fetch and save signing cert
    cert = _fetch_signing_cert()
    if cert:
        (version_dir / "signing_cert.json").write_text(
            json.dumps(cert, indent=2), encoding="utf-8"
        )
        logger.info("Signing cert saved")

    # Save manifest (without sig fields — consistent with what was signed)
    (version_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    # Compute Merkle leaf hash = sha256(canonical_json(manifest))
    merkle_hash = hashlib.sha256(_canonical_bytes(manifest)).hexdigest()

    # Register in Merkle transparency log
    _register_leaf(release_id, merkle_hash)

    # Update latest pointer
    LATEST_POINTER_PATH.write_text(
        json.dumps({"id": release_id}, indent=2), encoding="utf-8"
    )

    print(f"\n[+] Release created successfully!")
    print(f"    Version : {version}")
    print(f"    ID      : {release_id}")
    print(f"    SHA256  : {hashes['sha256']}")
    print(f"    Merkle  : {merkle_hash[:32]}...")
    print(f"    Dir     : {version_dir}\n")
