from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import log_store
import tree

router = APIRouter()


class LeafPayload(BaseModel):
    id: str
    hash: str


@router.get("/log")
async def get_log():
    entries = log_store.get_entries()
    hashes = [e["hash"] for e in entries]
    return {"root": tree.get_root(hashes), "entries": entries}


@router.get("/proof/{entry_id}")
async def get_proof(entry_id: str):
    entries = log_store.get_entries()
    hashes = [e["hash"] for e in entries]
    idx = next((i for i, e in enumerate(entries) if e["id"] == entry_id), None)
    if idx is None:
        return JSONResponse(status_code=404, content={"error": f"Entry '{entry_id}' not found"})
    proof = tree.get_proof(idx, hashes)
    return {"proof": proof, "root": tree.get_root(hashes)}


@router.get("/merkle-tree")
async def get_merkle_tree():
    entries = log_store.get_entries()
    hashes = [e["hash"] for e in entries]
    layers_raw = tree.build_tree(hashes)
    root = layers_raw[-1][0].hex() if layers_raw else None
    leaves = [layer.hex() for layer in layers_raw[0]] if layers_raw else []
    layers = [
        {"level": lvl, "hashes": [node.hex() for node in layer]}
        for lvl, layer in enumerate(layers_raw)
    ]
    return {"leaves": leaves, "root": root, "layers": layers}


@router.post("/leaf", status_code=201)
async def add_leaf(payload: LeafPayload):
    log_store.append_entry(payload.id, payload.hash)
    return {"id": payload.id, "hash": payload.hash}
