import argparse
import logging
from pathlib import Path
from urllib.parse import urljoin

import requests
from packaging import version
from requests import RequestException, Timeout

import config

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


def download_update_package(package_url: str, output_path: Path) -> None:
    logger.info("Downloading update package from %s", package_url)
    response = requests.get(package_url, stream=True, timeout=config.REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as file_handle:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                file_handle.write(chunk)

    logger.info("Update package saved to %s", output_path)


def run_update_check(server_url: str, local_version: str, download_dir: Path) -> int:
    try:
        manifest = fetch_manifest(server_url)
    except Timeout:
        logger.error("Manifest download timed out after %s seconds", REQUEST_TIMEOUT_SECONDS)
        return 1
    except RequestException as exc:
        logger.error("Cannot connect to server or invalid HTTP response: %s", exc)
        return 1
    except ValueError as exc:
        logger.error("Manifest is not valid JSON: %s", exc)
        return 1

    remote_version_raw = manifest.get("version")
    package_url = manifest.get("package_url")
    package_name = manifest.get("package_name", "update.zip")

    if not remote_version_raw or not package_url:
        logger.error("Manifest is missing required fields: version and package_url")
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
    try:
        download_update_package(str(package_url), output_path)
    except Timeout:
        logger.error("Package download timed out after %s seconds", REQUEST_TIMEOUT_SECONDS)
        return 1
    except RequestException as exc:
        logger.error("Package download failed (HTTP/network error): %s", exc)
        return 1
    except FileNotFoundError:
        logger.error("Cannot save update package - output path not found")
        return 1
    except OSError as exc:
        logger.error("Cannot save update package: %s", exc)
        return 1

    logger.info("Update downloaded successfully")
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
