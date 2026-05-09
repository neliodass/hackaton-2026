# Update Server

Serwer aktualizacji oparty na FastAPI. Serwuje manifest, podpis i paczki aktualizacji przez HTTP.

## Wymagania

```
pip install -r requirements.txt
```

## Uruchomienie

Odpal profil **Server** w PyCharm, lub:
```
python server/src/main.py
```

Domyślnie nasłuchuje na `http://127.0.0.1:8000`. Zmiana przez env var:
```
UPDATE_SERVER_HOST=0.0.0.0
UPDATE_SERVER_PORT=8000
```

## Podpisywanie manifestu

Serwer przy starcie automatycznie wysyła `server/packages/manifest.json` do signing machine i zapisuje zwrócony podpis jako `manifest.sig`. **Signing Machine musi być uruchomiona przed serwerem.**

Adres signing machine można zmienić przez env var:
```
SIGNING_MACHINE_URL=http://127.0.0.1:9000
```

## Endpointy

| Metoda | Ścieżka | Opis |
|---|---|---|
| GET | `/health` | Status serwera |
| GET | `/manifest` | Manifest aktualnej wersji (JSON) |
| GET | `/manifest.sig` | Podpis manifestu (binary) |
| GET | `/update.zip` | Paczka aktualizacji |
