# Task 09 — Protokół weryfikacji po stronie klienta

## Cel

Zaimplementować **deterministyczną kolejność** kroków weryfikacji (CLI, GUI, przyszły agent) — jedna funkcja `verify_update(manifest, authority_pub_pem, proof_response, log_root_expected) -> Result`.

## Provisioning zaufania

- Plik `client_authority_pub.pem` w katalogu roboczym **lub** `~/.qrbt_authority_pub.pem`.
- Brak pliku → twardy błąd przed jakimkolwiek requestem HTTP (fail-closed).

## Kolejność kroków (wymuszona)

1. **Pobierz** `GET /latest` → manifest `M`.
2. **Weryfikacja krypto manifestu** (task 05): authority cert + oba podpisy ephemeral. Jeśli FAIL → STOP (nie pobieraj binarki).
3. **Pobierz** `GET /proof/{M.id}` oraz `GET /log` (opcjonalnie tylko proof jeśli root jest w proof).
4. **Merkle**: odtwórz leaf = `SHA256(canonical_file_bytes(M))` — **uwaga:** po stronie klienta manifest jest z JSON; musisz użyć **identycznej** kanonikalizacji jak serwer przy hashowaniu do logu (najpewniej: sort_keys, separators, pola z `id`). Porównaj z `entries[i].hash` dla tego samego `id`.
5. Zweryfikuj proof względem `root` (wg spec z taska 04).
6. **Anti-rollback**: porównaj `M.version` ze stanem TPM (task 10).
7. **Pobierz** `/binary/{id}`.
8. `SHA256(data) == M.sha256` → zapis pliku + aktualizacja TPM.

## Współdzielenie kodu

- Pakiet `qrbt.client.verify` importuje `qrbt.crypto.canonical_json` — **zero duplikacji** z GUI.

## Kryteria ukończenia

- [ ] Funkcja `verify_manifest_crypto_only(manifest, authority_pub_pem) -> bool` pokryta testami jednostkowymi (wektor z zapisanego JSON z serwera).
- [ ] CLI używa tej samej funkcji co GUI.

## Pułapki

- Manifest z API może mieć inne formatowanie niż plik na dysku serwera — hash licz od **zdeserializowanego** dict przez `json.loads` + twoją funkcję canonical, nie od `response.text`.
