import json
from pathlib import Path
from typing import Optional

STATE_PATH = Path(__file__).resolve().parent.parent / "state.json"


def read_installed_version() -> Optional[str]:
    if not STATE_PATH.exists():
        return None
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return data.get("version")
    except (json.JSONDecodeError, OSError):
        return None


def write_installed_version(version: str) -> None:
    STATE_PATH.write_text(
        json.dumps({"version": version}, indent=2),
        encoding="utf-8",
    )
