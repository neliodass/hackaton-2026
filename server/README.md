# Update Server

Serwer aktualizacji z interfejsem CLI (bez GUI) udostępniający manifest i paczki przez HTTP(S).

## MVP endpoints

- `GET /health` - healthcheck
- `GET /manifest` - manifest aktualizacji (`server/packages/manifest.json`)
- `GET /update.zip` - paczka aktualizacji (`server/packages/update.zip`)

## Uruchomienie

```bash
pip install -r requirements.txt
python src/main.py
```
