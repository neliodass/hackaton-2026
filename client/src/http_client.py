import hashlib
import logging
from pathlib import Path
from urllib.parse import urljoin

import requests

import config

logger = logging.getLogger("update-client")


def fetch_manifest(server_url: str) -> dict:
    manifest_url = urljoin(server_url.rstrip("/") + "/", "manifest")
    logger.info("Downloading manifest from %s", manifest_url)
    response = requests.get(manifest_url, timeout=config.REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def fetch_signature(server_url: str) -> bytes:
    sig_url = server_url.rstrip("/") + "/manifest.sig"
    logger.info("Downloading manifest signature from %s", sig_url)
    response = requests.get(sig_url, timeout=config.REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.content


def download_update_package(
    package_url: str,
    output_path: Path,
    expected_sha256: str,
    expected_size_bytes: int,
    chunk_hashes: list | None = None,
    chunk_size: int = 1024 * 1024,
    progress_queue=None,
) -> str:
    """Download to .tmp, verify chunk hashes in-flight. Returns actual hex SHA-256."""
    size_limit = int(expected_size_bytes * 1.1)
    tmp_path = output_path.parent / (output_path.name + ".tmp")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Downloading update package from %s", package_url)
    response = requests.get(
        package_url,
        stream=True,
        timeout=config.REQUEST_TIMEOUT_SECONDS,
        verify=True,
    )
    response.raise_for_status()

    content_length = response.headers.get("Content-Length")
    if content_length is not None and int(content_length) > size_limit:
        logger.warning("[!] Server reports unexpected size. Aborting.")
        raise RuntimeError("Content-Length exceeds allowed size")

    full_hasher = hashlib.sha256()
    cumulative_bytes = 0
    buffer = bytearray()
    chunk_index = 0

    try:
        with tmp_path.open("wb") as fh:
            for http_chunk in response.iter_content(chunk_size=8192):
                if not http_chunk:
                    continue
                cumulative_bytes += len(http_chunk)
                if cumulative_bytes > size_limit:
                    logger.warning("[!] Server reports unexpected size. Aborting.")
                    raise RuntimeError("Downloaded size exceeds allowed size")
                full_hasher.update(http_chunk)
                fh.write(http_chunk)
                if progress_queue is not None:
                    progress_queue.put(cumulative_bytes)

                if chunk_hashes is not None:
                    buffer.extend(http_chunk)
                    while len(buffer) >= chunk_size:
                        segment = bytes(buffer[:chunk_size])
                        buffer = buffer[chunk_size:]
                        actual = hashlib.sha256(segment).hexdigest()
                        if actual != chunk_hashes[chunk_index]:
                            logger.warning(
                                "[!] SECURITY: Chunk %d hash mismatch. Expected %s, got %s. Aborting.",
                                chunk_index,
                                chunk_hashes[chunk_index],
                                actual,
                            )
                            raise RuntimeError(f"Chunk {chunk_index} hash mismatch")
                        logger.debug("Chunk %d OK (%s)", chunk_index, actual[:16])
                        chunk_index += 1

            if chunk_hashes is not None and buffer:
                segment = bytes(buffer)
                actual = hashlib.sha256(segment).hexdigest()
                if actual != chunk_hashes[chunk_index]:
                    logger.warning(
                        "[!] SECURITY: Chunk %d hash mismatch. Expected %s, got %s. Aborting.",
                        chunk_index,
                        chunk_hashes[chunk_index],
                        actual,
                    )
                    raise RuntimeError(f"Chunk {chunk_index} hash mismatch")
                logger.debug("Chunk %d OK (%s)", chunk_index, actual[:16])

    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    logger.info("[+] Downloaded %.2f MB", cumulative_bytes / (1024 * 1024))
    return full_hasher.hexdigest()
