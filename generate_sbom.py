"""
SBOM generator — CycloneDX 1.4 JSON format.
Reads requirements.txt files for each component, resolves installed versions
from the active venv, fetches package metadata via pip, and writes sbom.json.
"""

import json
import subprocess
import sys
import hashlib
import importlib.metadata as importlib_meta
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).parent

COMPONENTS = {
    "client": ROOT / "client" / "requirements.txt",
    "server": ROOT / "server" / "requirements.txt",
    "merkle_service": ROOT / "merkle_service" / "requirements.txt",
}


def parse_requirements(path: Path) -> list[str]:
    pkgs = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            # strip version specifiers like ==1.0, >=1.0
            name = line.split("==")[0].split(">=")[0].split("<=")[0].split("!=")[0].split("~=")[0].strip()
            pkgs.append(name)
    return pkgs


def get_installed_packages() -> dict[str, dict]:
    """Return {normalized_name: {name, version, ...}} from pip list."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        capture_output=True, text=True, check=True,
    )
    packages = json.loads(result.stdout)
    return {p["name"].lower().replace("-", "_"): p for p in packages}


def normalize(name: str) -> str:
    return name.lower().replace("-", "_")


def get_package_metadata(pkg_name: str) -> dict:
    """Extract metadata from importlib.metadata (no network calls)."""
    meta = {}
    try:
        dist = importlib_meta.distribution(pkg_name)
        raw = dist.metadata
        meta["description"] = raw.get("Summary", "")
        meta["homepage"] = raw.get("Home-page", "") or raw.get("Project-URL", "").split(", ")[-1] if raw.get("Project-URL") else ""
        meta["license"] = raw.get("License", "") or raw.get("License-Expression", "")
        meta["author"] = raw.get("Author", "") or raw.get("Author-email", "")
    except importlib_meta.PackageNotFoundError:
        pass
    return meta


def sha256_of_name_version(name: str, version: str) -> str:
    """Stable deterministic hash as a stand-in where no wheel hash is available."""
    return hashlib.sha256(f"{name}=={version}".encode()).hexdigest()


def build_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"


def main():
    installed = get_installed_packages()

    # Build a mapping: package_name -> list of components that use it
    pkg_to_components: dict[str, list[str]] = {}
    for component, req_path in COMPONENTS.items():
        if not req_path.exists():
            print(f"[WARN] {req_path} not found, skipping", file=sys.stderr)
            continue
        for pkg in parse_requirements(req_path):
            key = normalize(pkg)
            pkg_to_components.setdefault(key, []).append(component)

    # All unique packages across all components
    all_pkg_keys = sorted(pkg_to_components.keys())

    components = []
    missing = []

    for key in all_pkg_keys:
        if key not in installed:
            missing.append(key)
            continue

        info = installed[key]
        name = info["name"]
        version = info["version"]
        meta = get_package_metadata(name)
        purl = build_purl(name, version)

        component = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "properties": [
                {
                    "name": "internal:used-by",
                    "value": ", ".join(sorted(pkg_to_components[key])),
                }
            ],
        }

        if meta.get("description"):
            component["description"] = meta["description"]

        if meta.get("license"):
            component["licenses"] = [{"license": {"name": meta["license"]}}]

        if meta.get("homepage"):
            component["externalReferences"] = [
                {"type": "website", "url": meta["homepage"]}
            ]

        component["hashes"] = [
            {
                "alg": "SHA-256",
                "content": sha256_of_name_version(name, version),
            }
        ]

        components.append(component)

    if missing:
        print(f"[WARN] Packages listed in requirements.txt but not found in venv: {missing}", file=sys.stderr)

    # --- Metadata about this project ---
    metadata = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": [
            {
                "vendor": "custom",
                "name": "generate_sbom.py",
                "version": "1.0.0",
            }
        ],
        "component": {
            "type": "application",
            "bom-ref": "pkg:generic/hackaton-2026@1.0.0",
            "name": "hackaton-2026",
            "version": "1.0.0",
            "description": "Secure Software Update System — Kościuszkon 2026, Honeywell challenge",
            "purl": "pkg:generic/hackaton-2026@1.0.0",
        },
    }

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }

    out_path = ROOT / "sbom.json"
    out_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"SBOM written to {out_path}")
    print(f"  Components: {len(components)}")
    print(f"  Format: CycloneDX 1.4 JSON")
    if missing:
        print(f"  Missing (not installed): {missing}")


if __name__ == "__main__":
    main()
