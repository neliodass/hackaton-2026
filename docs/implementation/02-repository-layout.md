# Task 02 — Układ repozytorium (moduły i granice)

## Cel

Uniknąć monolitu `server.py` 400+ linii. Każdy moduł ma **jedną** wysokopoziomową odpowiedzialność (SRP na poziomie pakietu).

## Proponowany układ (nowe repo)

```text
src/
  qrbt/
    __init__.py
    crypto/
      __init__.py
      canonical_json.py    # jedna funkcja dumps_manifest_for_signing / cert_payload
      ed25519_ops.py
      mldsa_ops.py
    merkle/
      __init__.py
      tree.py              # MerkleTree + verify (ew. poprawiona)
    storage/
      __init__.py
      keys_store.py        # read/write keys.json + ephemeral files
      manifest_store.py    # manifests dir + log.json
    authority/
      __init__.py
      signer.py            # Protocol + implementacje (patrz task 06)
    server/
      __init__.py
      app.py                 # FastAPI factory create_app()
      routes.py              # lub routers/*.py
      cli.py                 # click group, importuje use-case’y
    client/
      __init__.py
      verify.py              # czysta funkcja verify_manifest(...)
      tpm.py
    models/
      manifest.py            # pydantic Manifest (zalecane)
tests/
  ...
scripts/
  export_authority_pub.py
pyproject.toml
```

## Przepływ zależności (wewnątrz `qrbt`)

- `server/cli` → `storage`, `crypto`, `authority`, `merkle`
- `client` → `crypto` (tylko verify), **nie** importuje `server`
- Wspólny kod kanonicznego JSON: **jeden moduł** `crypto/canonical_json.py` używany przez serwer i klienta (pakiet wspólny albo `qrbt_common` — w monorepo jedna biblioteka)

## Entrypointy

| Entrypoint | Moduł | Opis |
|------------|-------|------|
| `qrbt-server` | `qrbt.server.cli:main` | Click |
| `uvicorn qrbt.server.app:app` | `app = create_app()` | API |

## Kryteria ukończenia

- [ ] Brak cykli importów (np. `merkle` nie importuje `server`).
- [ ] Kanoniczny JSON manifestu/cert jest w **jednym** miejscu — test jednostkowy: dwa wywołania dają identyczne `bytes`.
- [ ] `AuthoritySigner` w osobnym pakiecie `authority/` — łatwe podmiany w testach.

## Pułapki

- Duplikacja `cert_payload` w `client_gui` i `client_cli` — w prototypie już jest ryzyko rozjazdu; w nowym repo **wspólny moduł**.
