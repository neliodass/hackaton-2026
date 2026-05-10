# Task 03 — Kontrakty danych na dysku

## Cel

Zdefiniować **dokładnie** co leży w `server_data/`, nazwy plików, kolejność operacji zapisu, tak aby drugi projekt mógł wymieniać implementację bez zmiany formatu (kompatybilność wsteczna opcjonalna).

## Katalogi

| Ścieżka | Zawartość |
|---------|-----------|
| `server_data/` | Root danych serwera |
| `server_data/manifests/` | `*.json` manifesty, `*.bin` binarki pod `id` |

## `server_data/keys.json`

Struktura JSON (minimalna):

```json
{
  "authority": {
    "priv": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n",
    "pub": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n"
  },
  "ephemeral": {
    "cert_sig_ed": "<hex Ed25519 signature over cert_payload>",
    "issued_at": 1710000000,
    "expires_at": 1710604800
  }
}
```

**Uwaga produkcyjna:** pole `authority.priv` może **nie istnieć** jeśli używasz wyłącznie `AuthoritySigner` zewnętrznego — wtedy `init` tworzy tylko `pub` + metadata, a podpis rotacji idzie z YubiKey. W wersji „demo plikowa” zostaw jak wyżej.

## Pliki ephemeral (obok `keys.json`)

| Plik | Format | Zawartość |
|------|--------|-----------|
| `ephemeral_ed.pem` | PEM PKCS8 | Prywatny Ed25519 ephemeral |
| `ephemeral_ed_pub.pem` | PEM SPKI | Publiczny Ed25519 ephemeral |
| `ephemeral_pqc.hex` | UTF-8 hex string | Sekret ML-DSA (jak `dilithium-py` zwraca z `keygen`) |
| `ephemeral_pqc_pub.hex` | UTF-8 hex string | Publiczny ML-DSA |

## `server_data/log.json`

```json
{
  "manifests": [
    { "id": "1710000001", "hash": "<sha256 hex>" },
    { "id": "1710000002", "hash": "<sha256 hex>" }
  ]
}
```

### Kontrakt `hash`

1. Manifest jest budowany **bez** pola `id`.
2. Podpisywany (ephemeral) — patrz task 05 — **bez** pól `ephemeral_sig_ed`, `ephemeral_sig_pqc` (i bez `id` jeśli nie jest w canonical subset).
3. Po zapisaniu pliku manifestu: nadawane jest `id` (np. timestamp string).
4. `hash = SHA256( canonical_json_bytes(manifest_with_id) )` w formacie **hex**.

**Krytyczne:** ten sam zestaw kluczy w `json.dumps(..., sort_keys=True)` co przy weryfikacji po stronie klienta dla fragmentu manifestu używanego do Merkle — ustal jedną funkcję `hash_manifest_file(dict) -> str`.

## Manifest `{id}.json` (po zapisie)

Pola (zgodnie z prototypem; nowe repo może dodać `schema_version`):

- `id`, `version`, `sha256`, `notes`, `binary_size`, `binary_name`
- `ephemeral_pub`, `ephemeral_pqc_pub`, `ephemeral_cert_sig_ed`
- `ephemeral_sig_ed`, `ephemeral_sig_pqc`

## Kolejność operacji `add_release` (atomowość logiczna)

1. Walidacja ephemeral (nie wygasły, pliki istnieją).
2. Zbuduj manifest **bez** `id` i bez sygnatur ephemeral.
3. `manifest_json = dumps_for_ephemeral_signing(manifest)`.
4. Podpisz Ed + ML-DSA → dopisz sygnatury.
5. `add_manifest`: nadaj `id`, zapisz JSON, dopisz do `log.json` z hashem **pełnego** manifestu z `id`.
6. Skopiuj binarkę do `{id}.bin`.

Jeśli krok 5 się uda a 6 nie — masz niespójność; w „lepszym” repo: zapis binarki **przed** commitem do logu albo transakcja „pending” + cleanup.

## Kryteria ukończenia

- [ ] Dokument + test: hash w logu == hash liczony przez klienta dla tego samego pliku manifestu.
- [ ] Zdefiniowane, które pola są wykluczane z JSON przed podpisem ephemeral (lista nazw w kodzie jako stała).
