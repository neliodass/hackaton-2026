import json
import threading
from typing import Optional

from config import LOG_PATH

_lock = threading.Lock()


def _ensure() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not LOG_PATH.exists():
        LOG_PATH.write_text(json.dumps({"entries": []}), encoding="utf-8")


def load_log() -> dict:
    _ensure()
    return json.loads(LOG_PATH.read_text(encoding="utf-8"))


def save_log(log: dict) -> None:
    LOG_PATH.write_text(json.dumps(log, indent=2), encoding="utf-8")


def get_entries() -> list[dict]:
    return load_log().get("entries", [])


def append_entry(entry_id: str, entry_hash: str) -> None:
    with _lock:
        log = load_log()
        log["entries"].append({"id": entry_id, "hash": entry_hash})
        save_log(log)


def find_entry(entry_id: str) -> tuple[Optional[int], Optional[dict]]:
    entries = get_entries()
    for idx, entry in enumerate(entries):
        if entry["id"] == entry_id:
            return idx, entry
    return None, None
