import json
import logging
import sys

import uvicorn

from app import app
from config import HOST, LATEST_POINTER_PATH, PORT, VERSIONS_DIR
from manifest import request_signature_from_signing_machine
from release import create_new_release

logger = logging.getLogger("update-server")

_MENU = f"""
╔══════════════════════════════════════╗
║       Update Server – Menu           ║
╠══════════════════════════════════════╣
║  1  Start server (port {PORT})        ║
║  2  Add new version                  ║
║  3  List all versions                ║
║  0  Exit                             ║
╚══════════════════════════════════════╝"""


def _list_versions() -> None:
    if not VERSIONS_DIR.exists() or not any(VERSIONS_DIR.iterdir()):
        print("\n  (no versions yet)\n")
        return

    latest_id = None
    if LATEST_POINTER_PATH.exists():
        try:
            latest_id = json.loads(LATEST_POINTER_PATH.read_text(encoding="utf-8")).get("id")
        except Exception:
            pass

    entries = []
    for version_dir in sorted(VERSIONS_DIR.iterdir()):
        if not version_dir.is_dir():
            continue
        manifest_path = version_dir / "manifest.json"
        if not manifest_path.exists():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        entries.append((version_dir, manifest))

    if not entries:
        print("\n  (no valid versions found)\n")
        return

    print(f"\n  {'VERSION':<12} {'ID':<38} {'SHA256':>16}  PATH")
    print("  " + "-" * 90)
    for version_dir, manifest in entries:
        ver = manifest.get("version", "?")
        rid = manifest.get("id", "?")
        sha = manifest.get("sha256", "?")[:16] + "..."
        marker = " ← latest" if rid == latest_id else ""
        print(f"  {ver:<12} {rid:<38} {sha}  {version_dir}{marker}")
    print()
    print(f"  Storage root: {VERSIONS_DIR}\n")


def interactive_menu() -> None:
    print(f"\nUpdate Server v1.0 | http://{HOST}:{PORT}")
    while True:
        print(_MENU)
        try:
            choice = input("Select option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

        if choice == "0":
            print("Goodbye.")
            sys.exit(0)

        elif choice == "1":
            print(f"\n[*] Requesting signatures from signing machine...")
            request_signature_from_signing_machine()
            print(f"[*] Starting server on http://{HOST}:{PORT} (press Ctrl+C to stop)...\n")
            try:
                uvicorn.run(app, host=HOST, port=PORT)
            except KeyboardInterrupt:
                print("\n[*] Server stopped. Back to menu.\n")

        elif choice == "2":
            try:
                version = input("Version string (e.g. 1.2.0): ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                continue
            if not version:
                print("[!] Version cannot be empty.")
                continue
            create_new_release(version)

        elif choice == "3":
            _list_versions()

        else:
            print(f"[!] Unknown option: {choice!r}")
