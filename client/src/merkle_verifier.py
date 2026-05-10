"""Client-side Merkle proof verification.

Hash conventions mirror merkle_service/tree.py exactly:
  - Entry hash:  sha256(canonical_json(manifest))  stored in the log
  - Leaf:        sha256(bytes.fromhex(entry_hash))
  - Proof step position: where the SIBLING sits
      "L" → sibling is LEFT  → sha256(sibling + current)
      "R" → sibling is RIGHT → sha256(current + sibling)
"""
import hashlib
import json


def _canonical_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def manifest_merkle_hash(manifest: dict) -> str:
    """Compute the hex SHA-256 that is stored as the log entry hash."""
    return hashlib.sha256(_canonical_bytes(manifest)).hexdigest()


def verify_proof(manifest: dict, proof: list[dict], expected_root: str) -> bool:
    """Return True if the Merkle proof reconstructs expected_root for manifest."""
    entry_hash = manifest_merkle_hash(manifest)
    cur = hashlib.sha256(bytes.fromhex(entry_hash)).digest()

    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        if step["position"] == "L":
            cur = hashlib.sha256(sibling + cur).digest()
        elif step["position"] == "R":
            cur = hashlib.sha256(cur + sibling).digest()
        else:
            return False

    return cur.hex() == expected_root
