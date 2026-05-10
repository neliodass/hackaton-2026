# Task 11 — Klient GUI (opcjonalny, zakres funkcjonalny)

## Cel

Jeśli zespół potrzebuje demo wizualnego: Tkinter (jak prototyp) lub inny framework — **logika weryfikacji identyczna z CLI** (import z `qrbt.client.verify`).

## Ekrany / zakres MVP

1. **Konfiguracja**: pole URL serwera (default `http://127.0.0.1:8000`).
2. **Log**: okno tekstowe z wynikami kroków weryfikacji (task 09).
3. **Przyciski**:
   - „Sprawdź aktualizacje” — pobierz `/latest`, verify crypto, `/proof`, TPM check (bez instalacji).
   - „Zainstaluj latest” — pełna ścieżka z zapisem binarki.
4. **Merkle** (opcjonalnie): `GET /merkle-tree`, rysowanie tekstowe lub prosty canvas — tylko prezentacja; nie duplikuj logiki krypto w UI.

## Wątki

- Requesty HTTP w `threading.Thread` lub `asyncio` + `async_tkinter` — żeby nie blokować UI.

## Kryteria ukończenia

- [ ] Jeden test manualny opisany w README (screenshot opcjonalny).
- [ ] Brak tajnych ścieżek do `authority` poza tym samym `load_authority_pub()` co CLI.

## Pułapki

- Tkinter na macOS wymaga `pythonw` — dokumentuj.
