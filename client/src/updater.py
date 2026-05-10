import logging
from pathlib import Path

from packaging import version
from requests import RequestException, Timeout

import config
from crypto.verifier import (
    is_cert_time_valid,
    verify_manifest_pq_signature,
    verify_manifest_signature,
    verify_signing_cert,
)
from http_client import (
    download_binary,
    fetch_latest_manifest,
    fetch_merkle_proof,
    fetch_versioned_cert,
    fetch_versioned_pq_signature,
    fetch_versioned_signature,
)
from merkle_verifier import verify_proof
from version_state import read_installed_version, write_installed_version

logger = logging.getLogger("update-client")

_PREVIEW_BYTES = 512  # how many bytes to hex-dump for binary files


def _preview_file(path: Path, package_name: str) -> None:
    """Log a human-readable preview of the downloaded file."""
    try:
        size = path.stat().st_size
        raw = path.read_bytes()
    except OSError as exc:
        logger.warning("Cannot read downloaded file for preview: %s", exc)
        return

    logger.info("=== Podgląd: %s (%d bajtów) ===", package_name, size)

    # Try UTF-8 text first
    try:
        text = raw.decode("utf-8")
        for line in text.splitlines():
            logger.info("  %s", line)
        logger.info("=== Koniec pliku ===")
        return
    except UnicodeDecodeError:
        pass

    # Binary fallback: hex dump first _PREVIEW_BYTES bytes
    chunk = raw[:_PREVIEW_BYTES]
    logger.info("  [plik binarny — hex dump pierwszych %d B]", len(chunk))
    for offset in range(0, len(chunk), 16):
        row = chunk[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
        logger.info("  %04x  %-47s  |%s|", offset, hex_part, asc_part)
    if size > _PREVIEW_BYTES:
        logger.info("  ... (%d bajtów pominięto)", size - _PREVIEW_BYTES)
    logger.info("=== Koniec podglądu ===")


def _check_root_keys() -> bool:
    if not config.EMBEDDED_ROOT_PUBLIC_KEY:
        logger.error(
            "EMBEDDED_ROOT_PUBLIC_KEY is not set — run 'python -m yubikey_mock keygen' "
            "and paste keys/root/root_ed25519_pub.hex into config.py"
        )
        return False
    if not config.EMBEDDED_ROOT_PQ_PUBLIC_KEY_HEX:
        logger.error(
            "EMBEDDED_ROOT_PQ_PUBLIC_KEY_HEX is not set — run 'python -m yubikey_mock keygen' "
            "and paste keys/root/root_mldsa_pub.hex into config.py"
        )
        return False
    return True


def run_update_check(server_url: str, local_version: str, download_dir: Path) -> int:
    if not _check_root_keys():
        return 1

    # ------------------------------------------------------------------
    # 1. Determine local version (state file takes priority over CLI arg)
    # ------------------------------------------------------------------
    stored = read_installed_version()
    effective_local = stored if stored is not None else local_version
    logger.info("Local version: %s%s", effective_local, " (from state.json)" if stored else "")

    # ------------------------------------------------------------------
    # 2. Fetch latest manifest from server
    # ------------------------------------------------------------------
    try:
        manifest = fetch_latest_manifest(server_url)
    except Timeout:
        logger.error("Manifest download timed out after %s seconds", config.REQUEST_TIMEOUT_SECONDS)
        return 1
    except RequestException as exc:
        logger.error("Cannot fetch /latest from server: %s", exc)
        return 1
    except ValueError as exc:
        logger.error("Latest manifest is not valid JSON: %s", exc)
        return 1

    remote_version_raw = manifest.get("version")
    release_id = manifest.get("id")

    if not remote_version_raw or not release_id:
        logger.error("Latest manifest is missing required fields: version and/or id")
        return 1

    # ------------------------------------------------------------------
    # 3. Version comparison
    # ------------------------------------------------------------------
    try:
        remote_ver = version.parse(str(remote_version_raw))
        local_ver = version.parse(effective_local)
    except Exception as exc:
        logger.error("Invalid version format: %s", exc)
        return 1

    logger.info("Server version: %s", remote_ver)

    if remote_ver <= local_ver:
        print(f"[+] Your software is up to date (version {effective_local}).")
        logger.info("No update required")
        return 0

    # ------------------------------------------------------------------
    # 4. Prompt user
    # ------------------------------------------------------------------
    print(f"\n[!] New version {remote_ver} available. Your version: {effective_local}.")
    try:
        answer = input("Download and install? [y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return 0

    if answer != "y":
        print("Update skipped.")
        return 0

    # ------------------------------------------------------------------
    # 5. Fetch + verify signing certificate
    # ------------------------------------------------------------------
    try:
        cert = fetch_versioned_cert(server_url, release_id)
    except Timeout:
        logger.error("Signing cert download timed out")
        return 1
    except RequestException as exc:
        logger.error("Cannot download signing certificate: %s", exc)
        return 1

    if not verify_signing_cert(cert, config.EMBEDDED_ROOT_PUBLIC_KEY, config.EMBEDDED_ROOT_PQ_PUBLIC_KEY_HEX):
        logger.error("Root key verification FAILED — signing certificate is not trusted. Aborting.")
        return 1
    logger.info("Signing certificate: root signatures OK")

    if not is_cert_time_valid(cert):
        logger.error(
            "Signing certificate expired or not yet valid (valid_from=%s valid_to=%s). Aborting.",
            cert.get("valid_from"), cert.get("valid_to"),
        )
        return 1
    logger.info("Signing certificate: validity period OK (%s → %s)", cert["valid_from"], cert["valid_to"])

    signing_pubkey = cert.get("signing_pubkey", {})
    signing_ed_pub = signing_pubkey.get("ed25519", "")
    signing_pq_pub = signing_pubkey.get("mldsa65", "")

    if not signing_ed_pub or not signing_pq_pub:
        logger.error("Signing certificate is missing signing_pubkey fields. Aborting.")
        return 1

    # ------------------------------------------------------------------
    # 6. Fetch + verify manifest signatures
    # ------------------------------------------------------------------
    try:
        signature = fetch_versioned_signature(server_url, release_id)
    except Timeout:
        logger.error("Ed25519 signature download timed out")
        return 1
    except RequestException as exc:
        logger.error("Cannot download Ed25519 signature: %s", exc)
        return 1

    if not verify_manifest_signature(manifest, signature, signing_ed_pub):
        logger.error("Ed25519 manifest verification FAILED — aborting update")
        return 1
    logger.info("Manifest: Ed25519 signature OK")

    try:
        pq_sig = fetch_versioned_pq_signature(server_url, release_id)
    except Timeout:
        logger.error("ML-DSA signature download timed out")
        return 1
    except RequestException as exc:
        logger.error("Cannot download ML-DSA signature: %s", exc)
        return 1

    if not verify_manifest_pq_signature(manifest, pq_sig, signing_pq_pub):
        logger.error("ML-DSA manifest verification FAILED — aborting update")
        return 1
    logger.info("Manifest: ML-DSA signature OK")

    # ------------------------------------------------------------------
    # 7. Merkle proof verification
    # ------------------------------------------------------------------
    try:
        proof_data = fetch_merkle_proof(config.MERKLE_SERVICE_URL, release_id)
    except Timeout:
        logger.error("Merkle proof fetch timed out — aborting update")
        return 1
    except RequestException as exc:
        logger.error("Cannot fetch Merkle proof: %s", exc)
        return 1

    proof = proof_data.get("proof", [])
    merkle_root = proof_data.get("root")

    if not merkle_root:
        logger.error("Merkle proof response missing root — aborting update")
        return 1

    if not verify_proof(manifest, proof, merkle_root):
        logger.error(
            "[!] SECURITY: Merkle proof verification FAILED for release %s. "
            "Manifest may not be in the transparency log. Aborting.",
            release_id,
        )
        return 1
    logger.info("Merkle proof: OK (root=%s...)", merkle_root[:16])

    # ------------------------------------------------------------------
    # 8. Download + verify binary
    # ------------------------------------------------------------------
    package_name = manifest.get("package_name", "update.txt")
    expected_sha256 = manifest.get("sha256")
    expected_size_bytes = manifest.get("size_bytes")
    chunk_hashes = manifest.get("chunk_hashes")
    chunk_size = manifest.get("chunk_size", 1024 * 1024)

    if not expected_sha256 or not expected_size_bytes:
        logger.error("Manifest is missing required security fields: sha256 and/or size_bytes")
        return 1

    output_path = download_dir / package_name
    tmp_path = output_path.parent / (output_path.name + ".tmp")

    try:
        actual_hash = download_binary(
            server_url,
            release_id,
            output_path,
            expected_size_bytes=expected_size_bytes,
            chunk_hashes=chunk_hashes,
            chunk_size=chunk_size,
        )
    except Timeout:
        logger.error("Package download timed out")
        return 1
    except RuntimeError as exc:
        logger.error("Package download aborted: %s", exc)
        return 1
    except RequestException as exc:
        logger.error("Package download failed: %s", exc)
        tmp_path.unlink(missing_ok=True)
        return 1
    except OSError as exc:
        logger.error("Cannot save update package: %s", exc)
        tmp_path.unlink(missing_ok=True)
        return 1

    if actual_hash != expected_sha256:
        logger.warning(
            "[!] SECURITY: Hash mismatch. Expected %s, got %s. Possible tampering. Aborting.",
            expected_sha256, actual_hash,
        )
        tmp_path.unlink(missing_ok=True)
        return 1

    logger.info("[+] Hash verified: %s", actual_hash)
    tmp_path.replace(output_path)

    # ------------------------------------------------------------------
    # 9. Preview downloaded file
    # ------------------------------------------------------------------
    _preview_file(output_path, package_name)

    # ------------------------------------------------------------------
    # 10. Save new version to state
    # ------------------------------------------------------------------
    write_installed_version(str(remote_ver))
    print(f"\n[+] Update successful! Installed version: {remote_ver}")
    print(f"    File saved to: {output_path}")
    return 0
