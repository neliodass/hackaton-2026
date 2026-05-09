import argparse
import hashlib
import logging
from pathlib import Path
from urllib.parse import urljoin

import requests
from packaging import version
from requests import RequestException, Timeout

import config
from crypto.verifier import verify_manifest_signature

DEFAULT_DOWNLOAD_DIR = Path(__file__).resolve().parent.parent / "downloads"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | update-client | %(message)s",
)
logger = logging.getLogger("update-client")


def fetch_manifest(server_url: str) -> dict:
    manifest_url = urljoin(server_url.rstrip("/") + "/", "manifest")
    logger.info("Downloading manifest from %s", manifest_url)
    response = requests.get(manifest_url, timeout=config.REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def download_update_package(
    package_url: str,
    output_path: Path,
    expected_sha256: str,
    expected_size_bytes: int,
    chunk_hashes: list | None = None,
    chunk_size: int = 1024 * 1024,
    progress_queue=None,
) -> str:
    """Download to .tmp, compute SHA-256 streamingly. Returns actual hex SHA-256."""
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

    mb = cumulative_bytes / (1024 * 1024)
    logger.info("[+] Downloaded %.2f MB", mb)
    return full_hasher.hexdigest()


def fetch_signature(server_url: str) -> bytes:
    sig_url = server_url.rstrip("/") + "/manifest.sig"
    logger.info("Downloading manifest signature from %s", sig_url)
    response = requests.get(sig_url, timeout=config.REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.content


def run_update_check(server_url: str, local_version: str, download_dir: Path) -> int:
    if not config.EMBEDDED_PUBLIC_KEY:
        logger.error("EMBEDDED_PUBLIC_KEY is not set in public_key.py — cannot verify manifest")
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
        logger.error("Manifest signature verification FAILED — aborting update")
        return 1

    logger.info("Manifest signature verified OK")

    remote_version_raw = manifest.get("version")
    package_url = manifest.get("package_url")
    package_name = manifest.get("package_name", "update.zip")

    if not remote_version_raw or not package_url:
        logger.error("Manifest is missing required fields: version and package_url")
        return 1

    expected_sha256 = manifest.get("sha256")
    expected_size_bytes = manifest.get("size_bytes")

    if not expected_sha256 or not expected_size_bytes:
        logger.error(
            "Manifest is missing required security fields: sha256 and/or size_bytes — aborting"
        )
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Software Update Client (MVP)")
    parser.add_argument("--server-url", default=config.SERVER_URL, help="Update server base URL")
    parser.add_argument("--local-version", default=config.LOCAL_VERSION, help="Current local app version")
    parser.add_argument(
        "--download-dir",
        default=str(DEFAULT_DOWNLOAD_DIR),
        help="Directory where update package should be saved",
    )
    args = parser.parse_args()

    exit_code = run_update_check(
        server_url=args.server_url,
        local_version=args.local_version,
        download_dir=Path(args.download_dir),
    )
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
