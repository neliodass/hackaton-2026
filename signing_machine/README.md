# Signing Machine

Serwer HTTP działający na laptopie release managera. Odbiera manifest JSON od serwera aktualizacji i zwraca podpis Ed25519. Klucz prywatny nigdy nie opuszcza tej maszyny.

## Setup (jednorazowy)

**1. Odpal profil `Keygen` w PyCharm** — pyta o hasło i generuje parę kluczy Ed25519.

**2. Wklej wypisany hex do `client/src/public_key.py`:**
```python
EMBEDDED_PUBLIC_KEY: str = "<hex_z_keygen>"
```

**3. Dodaj hasło do konfiguracji Signing Machine:**
`Edit Configurations → Signing Machine → Environment variables`
```
SIGNING_KEY_PASSWORD=twoje_haslo
```
Jeśli klucz bez hasła — pomiń ten krok.

> `Signing_Machine.xml` jest w `.gitignore` — każdy release manager konfiguruje go lokalnie.

## Uruchomienie

Odpal profil **Signing Machine** w PyCharm przed uruchomieniem serwera. Nasłuchuje na `127.0.0.1:9000`.

Serwer automatycznie wysyła manifest do signing machine przy starcie jeśli podpis jest nieaktualny.
