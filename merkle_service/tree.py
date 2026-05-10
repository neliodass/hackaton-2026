import hashlib
from typing import Optional


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_tree(entry_hashes: list[str]) -> list[list[bytes]]:
    """Build Merkle tree layers from a list of hex SHA-256 entry hashes.

    Layer 0 = leaves = sha256(bytes.fromhex(entry_hash))
    Each subsequent layer halves the count; odd count → duplicate last node.
    Returns list of layers (layer 0 = leaves, last layer = [root]).
    """
    if not entry_hashes:
        return []

    layer: list[bytes] = [_sha256(bytes.fromhex(h)) for h in entry_hashes]
    layers: list[list[bytes]] = [layer]

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer = layer + [layer[-1]]
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            next_layer.append(_sha256(layer[i] + layer[i + 1]))
        layer = next_layer
        layers.append(layer)

    return layers


def get_root(entry_hashes: list[str]) -> Optional[str]:
    layers = build_tree(entry_hashes)
    if not layers:
        return None
    return layers[-1][0].hex()


def get_proof(idx: int, entry_hashes: list[str]) -> list[dict]:
    """Return Merkle inclusion proof for entry at idx.

    Each proof step: {"hash": "<hex>", "position": "L"|"R"}
    position = where the SIBLING sits:
      "L" → sibling is left  → verifier computes sha256(sibling + current)
      "R" → sibling is right → verifier computes sha256(current + sibling)
    """
    layers = build_tree(entry_hashes)
    if not layers or idx >= len(layers[0]):
        return []

    proof: list[dict] = []
    current_idx = idx

    for layer in layers[:-1]:
        padded = layer + ([layer[-1]] if len(layer) % 2 == 1 else [])
        if current_idx % 2 == 0:
            sibling_idx = current_idx + 1
            proof.append({"hash": padded[sibling_idx].hex(), "position": "R"})
        else:
            sibling_idx = current_idx - 1
            proof.append({"hash": padded[sibling_idx].hex(), "position": "L"})
        current_idx //= 2

    return proof
