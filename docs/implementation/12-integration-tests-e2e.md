# Task 12 — Testy integracyjne i scenariusze „ataków”

## Cel

Automatyczna ścieżka: czyste `server_data`, `init`, `rotate`, N×`add-release`, start API, klient — assert exit code / pliki wyjściowe.

## Szablon testu E2E (pytest)

1. `tmp_path` jako `SERVER_DATA` przez env `QRBT_DATA_DIR` (nowe repo **powinno** wspierać override katalogu danych zamiast hardcode `Path(__file__).parent`).
2. Subprocess lub `TestClient` Starlette dla API bez portu.
3. Ustaw `HOME=tmp_path` żeby TPM mock trafiał do izolowanego profilu.

## Minimalna lista testów

| Nazwa | Kroki | Oczekiwany wynik |
|-------|--------|------------------|
| `test_happy_install` | init→rotate→release→client | exit 0, plik `installed_*.bin`, TPM zaktualizowany |
| `test_bad_authority_pub` | jak wyżej ale zły PEM u klienta | weryfikacja FAIL przed downloadem |
| `test_sha_mismatch` | serwer zwraca zły bin (mock endpoint) | klient odrzuca |
| `test_expired_ephemeral` | ustaw `expires_at` w przeszłość | `add-release` fail |
| `test_mock_yubikey_locked` | rotate bez unlock | wyjątek / exit ≠ 0 |

## Narzędzia

- `pytest`, `httpx` + `ASGITransport` **albo** `fastapi.testclient.TestClient`.
- Dla subprocess CLI: `subprocess.run([...], check=True, env=...)`.

## Kryteria ukończenia

- [ ] CI (GitHub Actions): `pytest -q` na push.
- [ ] Jeden test używa `MockYubiKeySigner` przez injekcję (nie przez prawdziwy plik keys.json z priv).

## Pułapki

- Porty wolne: preferuj `TestClient` zamiast losowego portu uvicorn.
