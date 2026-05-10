# Task 00 — Wymagania wstępne i słownik

## Cel

Ujednolicić środowisko i terminologię przed implementacją, żeby kolejne taski nie rozjeżdżały się co do znaczenia pól JSON i ról kluczy.

## Wymagania środowiskowe

- **Python**: 3.11+ (zalecane 3.12). Uzasadnienie: stabilne wheel’e dla `cryptography`, mniej problemów z `dilithium-py`.
- **System**: Linux lub macOS do developmentu; Windows możliwy, ale PKCS#11/YubiKey mock przez subprocess testuj osobno.
- **Narzędzia**: `pip`, `venv`, opcjonalnie `uv`.

## Zależności runtime (minimalny zestaw)

| Pakiet | Rola |
|--------|------|
| `cryptography` | Ed25519, PEM, serializacja |
| `dilithium-py` | ML-DSA-65 (podpis PQC na manifeście) |
| `fastapi`, `uvicorn` | API serwera |
| `click` | CLI serwera |
| `requests` | Klient CLI (lub `httpx`) |
| `pydantic` | Opcjonalnie: modele manifestu (zalecane w „czystym” repo) |

## Słownik pojęć

| Termin | Znaczenie |
|--------|-----------|
| **Authority (root)** | Długoterminowy klucz **Ed25519**, który *tylko* certyfikuje powiązanie dwóch kluczy publicznych **ephemeral** (klasyczny Ed25519 + ML-DSA public) w jednym `cert_payload`. Prywatny authority **nie** powinien być na hoście release w wersji produkcyjnej — tylko za abstrakcją `AuthoritySigner`. |
| **Ephemeral keys** | Para podpisów manifestu: klucz Ed25519 + klucz ML-DSA-65, rotowane co N dni. Prywatne ephemeral są na serwerze budującym release (mniej krytyczne niż authority). |
| **cert_payload** | Kanoniczny JSON (UTF-8) z polami `ephemeral_pub` (PEM) i `ephemeral_pqc_pub` (hex), `sort_keys=True`, **bez** spacji — identyczny bajt po bajcie po stronie serwera i klienta. |
| **manifest** | JSON metadanych wydania + klucze pub ephemeral + `ephemeral_cert_sig_ed` + podpisy `ephemeral_sig_ed`, `ephemeral_sig_pqc`. Pole `id` nadawane przy zapisie. |
| **Transparency log** | Lista `{id, hash}` gdzie `hash = SHA256(hex lub bytes)` **kanonicznej** reprezentacji JSON manifestu po dodaniu `id` — kontrakt opisany w `03-data-on-disk-contracts.md`. |
| **TPM (mock)** | Lokalny stan „ostatnia zainstalowana wersja” — plik JSON; symulacja polityki anti-rollback. |

## Kryteria ukończenia taska 00

- [ ] Zespół akceptuje powyższe definicje (ew. dopisuje własne terminy do README głównego nowego repo).
- [ ] Ustalony jest format wersji (semver strict vs string) — patrz `10-tpm-mock-and-version-policy.md`.

## Pułapki

- **„Root” vs „authority”**: w kodzie badawczym jest `authority`; w dokumentacji zewnętrznej możesz mówić „root key” — to ta sama rola.
- **ML-DSA public w manifeście**: przechowywany jako **hex** (jak w prototypie); nowe repo musi to utrwalić w jednym miejscu (stała / typ).
