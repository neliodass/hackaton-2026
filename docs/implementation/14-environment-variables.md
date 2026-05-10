# Task 14 — Zmienne środowiskowe i konfiguracja (referencja)

## Cel

Jedna tabela konfiguracji dla odtworzenia projektu w CI, na laptopie i przy demo YubiKey mock — bez grzebania w kodzie.

## Zmienne (propozycja dla nowego repo)

| Zmienna | Gdzie używana | Domyślna wartość | Opis |
|---------|---------------|------------------|------|
| `QRBT_DATA_DIR` | serwer, CLI | `./server_data` lub ścieżka względem cwd | **Wymagane w teście E2E** — izolacja `tmp_path`. |
| `QRBT_AUTHORITY_BACKEND` | CLI `init`, `rotate` | `file` | `file` \| `mock_yubikey` \| `injected` (tylko hex z zewnątrz). |
| `QRBT_MOCK_YUBIKEY_PIN` | `MockYubiKeySigner` | `123456` | PIN do odblokowania mocka. |
| `QRBT_MOCK_YUBIKEY_LATENCY_MS` | mock | `0` | Symulacja opóźnienia tokenu. |
| `QRBT_MOCK_YUBIKEY_SEED` | mock (opcjonalnie) | brak | Jeśli ustawione (hex 64 znaków): deterministyczny klucz z seeda (implementacja wg uznania). |
| `HOME` / `USERPROFILE` | klient TPM | system | Testy ustawiają `HOME` na tymczasowy katalog. |

## URL serwera (klient)

- Stała w module klienta lub env `QRBT_SERVER_URL` (default `http://127.0.0.1:8000`) — ułatwia testy przeciwko `TestClient` przez subprocess z innym portem.

## Kryteria ukończenia

- [ ] Wszystkie zmienne wymienione w głównym `README.md` nowego repo.
- [ ] `qrbt-server --help` nie wypisuje sekretów przy debugowaniu.
