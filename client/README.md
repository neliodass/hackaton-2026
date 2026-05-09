# Update Client

Klient aktualizacji w Pythonie. Pobiera manifest z serwera, weryfikuje podpis Ed25519 i pobiera paczkę jeśli dostępna jest nowsza wersja.

## Wymagania

```
pip install -r requirements.txt
```

## Setup klucza publicznego

Klucz publiczny jest zaszyty w kodzie klienta. Po wygenerowaniu kluczy przez signing machine wklej hex do `client/src/config.py`:
```python
EMBEDDED_PUBLIC_KEY = "<hex_z_keygen>"
```

## Uruchomienie

Odpal profil **Client** w PyCharm, lub:
```
python client/src/main.py
```

Domyślne parametry można nadpisać przez env var lub argumenty CLI:
```
python client/src/main.py --server-url http://127.0.0.1:8000 --local-version 1.0.0
```

| Env var | Domyślnie | Opis |
|---|---|---|
| `UPDATE_SERVER_URL` | `http://127.0.0.1:8000` | Adres serwera aktualizacji |
| `UPDATE_LOCAL_VERSION` | `1.0.0` | Aktualna wersja aplikacji |
| `UPDATE_REQUEST_TIMEOUT` | `10` | Timeout HTTP w sekundach |
