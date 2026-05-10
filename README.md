# Secure Software Update System

Monorepo dla projektu konkursowego Kościuszkon 2026 (Honeywell #1).

## Struktura

- `client/` – Update Client (Python + Tkinter)
- `server/` – Update Server (FastAPI)
- `signing_machine/` – Signing Machine (FastAPI)
- `yubikey_mock/` – Mock sprzętowego klucza YubiKey
- `keys/` – materiały kryptograficzne (klucze prywatne wykluczone z repo)

---

## Uruchomienie od zera

### 1. YubiKey → opcja `1 Keygen`

Generuje parę kluczy root (Ed25519 + ML-DSA). Na pytanie o PIN naciśnij Enter (bez PINu) lub wpisz hasło.

Po zakończeniu skopiuj wygenerowane klucze publiczne do `client/src/config.py`:
- zawartość `keys/root/root_ed25519_pub.hex` → `EMBEDDED_ROOT_PUBLIC_KEY`
- zawartość `keys/root/root_mldsa_pub.hex` → `EMBEDDED_ROOT_PQ_PUBLIC_KEY_HEX`

---

### 2. Keygen

Generuje klucze signing machine. Na pytanie o hasło naciśnij Enter (bez hasła) lub wpisz hasło.

Jeśli ustawiłeś hasło, wpisz je też w run configu **Signing Machine** jako zmienną środowiskową `SIGNING_KEY_PASSWORD`.

---

### 3. YubiKey → opcja `2 Certify`

Ceremonia podpisania certyfikatu — root key autoryzuje signing machine na 7 dni.

- PIN YubiKey'a: ten sam co w kroku 1
- Hasło signing machine: ten sam co w kroku 2
- Symulacja dotyku: naciśnij Enter

Efekt: powstaje `keys/signing_cert.json`.

---

### 4. Signing Machine

Uruchom i zostaw działający. Udostępnia klucze i certyfikat dla serwera.

---

### 5. Server

Uruchom i zostaw działający. Przy starcie automatycznie pobiera podpisy i certyfikat od signing machine.

---

### 6. Client

Weryfikuje pełny łańcuch: `root key → certyfikat → signing key → manifest → paczka`.

---

## Po tygodniu (rotacja kluczy)

Powtórz kroki **2 → 3** (nowe klucze signing machine + nowy certyfikat). Kroki 1 i edycja `config.py` nie są potrzebne.
