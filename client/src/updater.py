import logging
from pathlib import Path

from packaging import version
from requests import RequestException, Timeout

import config
from crypto.verifier import verify_manifest_pq_signature, verify_manifest_signature
from http_client import (
    download_update_package,
    fetch_manifest,
    fetch_pq_signature,
    fetch_signature,
)

logger = logging.getLogger("update-client")


def run_update_check(server_url: str, local_version: str, download_dir: Path) -> int:
    if not config.EMBEDDED_PUBLIC_KEY:
        logger.error("EMBEDDED_PUBLIC_KEY is not set in config.py — cannot verify manifest")
        return 1
    if not config.EMBEDDED_PQ_PUBLIC_KEY_HEX:
        logger.error("EMBEDDED_PQ_PUBLIC_KEY_HEX is not set in config.py — cannot verify manifest")
        return 1

    try:
        manifest = fetch_manifest(server_url)
    except Timeout:
        logger.error("Manifest download timed out after %s seconds", config.REQUEST_TIMEOUT_SECONDS)
        return 1
    except RequestException as exc:
        logger.error("Cannot connect to server or invalid HTTP response: %s", exc)
        return 1
    except ValueError as exc:
        logger.error("Manifest is not valid JSON: %s", exc)
        return 1

    try:
        signature = fetch_signature(server_url)
    except Timeout:
        logger.error("Signature download timed out after %s seconds", config.REQUEST_TIMEOUT_SECONDS)
        return 1
    except RequestException as exc:
        logger.error("Cannot download manifest signature: %s", exc)
        return 1

    if not verify_manifest_signature(manifest, signature, config.EMBEDDED_PUBLIC_KEY):
        logger.error("Hybrid signing: Ed25519 verification FAILED — aborting update")
        return 1

    logger.info("Hybrid signing: Ed25519 manifest signature OK")

    try:
        pq_sig = fetch_pq_signature(server_url)
    except Timeout:
        logger.error("Hybrid signing: ML-DSA signature download timed out after %s seconds", config.REQUEST_TIMEOUT_SECONDS)
        return 1
    except RequestException as exc:
        logger.error("Hybrid signing: cannot download manifest.pq.sig (%s)", exc)
        return 1

    if not verify_manifest_pq_signature(manifest, pq_sig, config.EMBEDDED_PQ_PUBLIC_KEY_HEX):
        logger.error("Hybrid signing: ML-DSA verification FAILED — aborting update")
        return 1

    logger.info("Hybrid signing: PQ ML-DSA manifest signature OK")

    remote_version_raw = manifest.get("version")
    package_url = manifest.get("package_url")
    package_name = manifest.get("package_name", "update.zip")

    if not remote_version_raw or not package_url:
        logger.error("Manifest is missing required fields: version and package_url")
        return 1

    expected_sha256 = manifest.get("sha256")
    expected_size_bytes = manifest.get("size_bytes")

    if not expected_sha256 or not expected_size_bytes:
        logger.error("Manifest is missing required security fields: sha256 and/or size_bytes — aborting")
        return 1

    try:
        remote_version = version.parse(str(remote_version_raw))
        current_version = version.parse(local_version)
    except Exception as exc:
        logger.error("Invalid version format: %s", exc)
        return 1

    logger.info("Local version: %s | Server version: %s", current_version, remote_version)
    if remote_version <= current_version:
        logger.info("No update required")
        return 0

    output_path = download_dir / package_name
    tmp_path = output_path.parent / (output_path.name + ".tmp")
    chunk_hashes = manifest.get("chunk_hashes")
    chunk_size = manifest.get("chunk_size", 1024 * 1024)

    if chunk_hashes:
        logger.info("Chunk verification enabled (%d chunks, %d B each)", len(chunk_hashes), chunk_size)

    try:
        actual_hash = download_update_package(
            str(package_url),
            output_path,
            expected_sha256=expected_sha256,
            expected_size_bytes=expected_size_bytes,
            chunk_hashes=chunk_hashes,
            chunk_size=chunk_size,
        )
    except Timeout:
        logger.error("Package download timed out after %s seconds", config.REQUEST_TIMEOUT_SECONDS)
        return 1
    except RuntimeError as exc:
        logger.error("Package download aborted: %s", exc)
        return 1
    except RequestException as exc:
        logger.error("Package download failed (HTTP/network error): %s", exc)
        tmp_path.unlink(missing_ok=True)
        return 1
    except OSError as exc:
        logger.error("Cannot save update package: %s", exc)
        tmp_path.unlink(missing_ok=True)
        return 1

    if actual_hash != expected_sha256:
        logger.warning(
            "[!] SECURITY: Hash mismatch. Expected %s, got %s. Possible tampering. Aborting.",
            expected_sha256,
            actual_hash,
        )
        tmp_path.unlink(missing_ok=True)
        return 1

    logger.info("[+] Hash verified: %s", actual_hash)
    tmp_path.replace(output_path)
    logger.info("Update downloaded successfully to %s", output_path)
    return 0
