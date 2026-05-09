import argparse
import logging
from pathlib import Path

import config
from updater import run_update_check

DEFAULT_DOWNLOAD_DIR = Path(__file__).resolve().parent.parent / "downloads"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | update-client | %(message)s",
)


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
