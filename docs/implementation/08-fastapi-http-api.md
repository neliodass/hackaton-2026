# Task 08 — HTTP API (FastAPI)

## Cel

Odtworzyć endpointy z zachowaniem semantycznym prototypu, z możliwością dodania middleware (CORS, request ID) w nowym repo.

## Lista endpointów

| Metoda | Ścieżka | Zachowanie |
|--------|---------|------------|
| GET | `/keys` | Prototyp zwraca `{}` — **celowo nie wycieka** `authority_pub`. Zachowaj to albo zwróć tylko `{"schema":...}` bez kluczy. |
| GET | `/latest` | Ostatni wpis z `log.json` → wczytaj `{id}.json`; 404 jeśli brak manifestów lub pliku. |
| GET | `/manifest/{id}` | Plik JSON; 404. |
| GET | `/binary/{id}` | `FileResponse` dla `{id}.bin`; 404. |
| GET | `/log` | `{ root, entries }` z Merkle (task 04). |
| GET | `/proof/{id}` | Dowód + root; 404 jeśli id nie w logu. |
| GET | `/merkle-tree` | Struktura warstw pod GUI. |

## Kody HTTP

- 404 dla brakujących zasobów.
- 500 tylko dla nieobsłużonych wyjątków — loguj stack trace po stronie serwera.

## Bezpieczeństwo API (minimum na przyszłość)

- Nagłówek `X-Content-Type-Options: nosniff` (middleware Starlette).
- Opcjonalnie: rate limit na `/binary` (poza MVP).

## Kryteria ukończenia

- [ ] Test HTTP (httpx AsyncClient lub requests): ścieżka happy path `/latest` → `/proof` → `/binary`.
- [ ] `/keys` nie zawiera PEM authority (grep w teście).

## Pułapki

- `JSONResponse(content=dict)` — FastAPI serializuje `dict`; upewnij się że kolejność kluczy w odpowiedzi **nie** wpływa na weryfikację (wpływa tylko zapisany plik na dysku).
