# Task 05 — Kryptografia: certyfikat ephemeral + podpisy manifestu

## Cel

Zaimplementować **dwa poziomy** podpisów:

1. **Authority (Ed25519)** — podpisuje wyłącznie `cert_payload` wiążący oba klucze publiczne ephemeral.
2. **Ephemeral (Ed25519 AND ML-DSA-65)** — podpisują **ten sam** bajtowy `manifest_json` zdefiniowany poniżej.

## `cert_payload` (identycznie serwer + klient)

```python
import json

def build_cert_payload(ephemeral_pub_pem: str, ephemeral_pqc_pub_hex: str) -> bytes:
    # Wersja badawcza: json.dumps(..., sort_keys=True) — domyślne separatory Pythona (", ", ": ").
    # Nowe repo: możesz przejść na separators=(",", ":") pod warunkiem że SERWER i KLIENT
    # oraz testy wektorów użyją tej samej funkcji — inaczej rozjedzie się weryfikacja.
    return json.dumps(
        {
            "ephemeral_pub": ephemeral_pub_pem,
            "ephemeral_pqc_pub": ephemeral_pqc_pub_hex,
        },
        sort_keys=True,
    ).encode("utf-8")
```

- Sygnatura authority: `Ed25519.sign(authority_sk, cert_payload)` → hex w polu manifestu `ephemeral_cert_sig_ed` (nazwa historyczna z prototypu; w nowym repo możesz nazwać `authority_cert_sig`).

## Manifest przed podpisem ephemeral

Bazowy słownik (bez `id`, bez `ephemeral_sig_*`):

- `version`, `sha256`, `notes`, `binary_size`, `binary_name`
- `ephemeral_pub`, `ephemeral_pqc_pub`, `ephemeral_cert_sig_ed`

### `manifest_json` do podpisu ephemeral

```python
EXCLUDED = frozenset({"ephemeral_sig_ed", "ephemeral_sig_pqc", "id"})

def dumps_for_ephemeral_signing(manifest: dict) -> bytes:
    subset = {k: manifest[k] for k in manifest if k not in EXCLUDED}
    return json.dumps(subset, sort_keys=True).encode("utf-8")
```

**Weryfikacja po stronie klienta** musi użyć **tej samej** funkcji (wspólny moduł).

## Podpisywanie

1. `sig_ed = ephemeral_ed_sk.sign(manifest_json)` → hex w `ephemeral_sig_ed`.
2. `sig_pqc = ML_DSA_65.sign(bytes.fromhex(eph_pqc_priv), manifest_json)` → hex w `ephemeral_sig_pqc`.

## Weryfikacja (kolejność)

1. Z manifestu: `ephemeral_pub`, `ephemeral_pqc_pub`, `ephemeral_cert_sig_ed`.
2. `cert_payload = build_cert_payload(ephemeral_pub, ephemeral_pqc_pub)`.
3. `authority_pub.verify(bytes.fromhex(ephemeral_cert_sig_ed), cert_payload)`.
4. `manifest_json = dumps_for_ephemeral_signing(manifest)`.
5. `ephemeral_ed_pub.verify(bytes.fromhex(ephemeral_sig_ed), manifest_json)`.
6. `ML_DSA_65.verify(bytes.fromhex(ephemeral_pqc_pub), manifest_json, bytes.fromhex(ephemeral_sig_pqc))`.

## Kryteria ukończenia

- [ ] Test: zmiana jednego znaku w `notes` po podpisaniu → oba podpisy ephemeral fail.
- [ ] Test: podmiana `ephemeral_pub` bez zmiany `ephemeral_cert_sig_ed` → fail na kroku 3.
- [ ] Test: usunięcie jednego z podpisów ephemeral → fail (AND).

## Pułapki

- **Jedna funkcja** `dumps_for_ephemeral_signing` / `build_cert_payload` współdzielona — każda zmiana `separators` lub `ensure_ascii` łamie zgodność z już wydanymi manifestami.
- ML-DSA klucze w hex: `dilithium-py` zwraca `bytes`; konwersja `bytes.hex()` / `bytes.fromhex()` musi być symetryczna.
