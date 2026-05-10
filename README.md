# Secure Software Update System

Monorepo dla projektu konkursowego Kościuszkon 2026 (Honeywell #1).

## Struktura

- `client/` – Update Client (Python + Tkinter)
- `server/` – Update Server (FastAPI)
- `signing_machine/` – Signing Machine (FastAPI)
- `yubikey_mock/` – Mock sprzętowego klucza YubiKey
- `keys/` – materiały kryptograficzne (klucze prywatne wykluczone z repo)
- `certs/` – lokalne pliki TLS (generowane, nie commituj); `scripts/gen_local_https_cert.py`
- `scripts/` – m.in. generowanie certu pod **HTTPS tylko na 127.0.0.1** (pokaz, bez domeny)

### HTTPS lokalnie (bez kupowania domeny)

**Zanim pierwszy raz odpalisz Server**, wygeneruj certyfikat i klucz do folderu `certs/`:

- W PyCharm: konfiguracja uruchomienia **„Gen Local HTTPS Cert”** (ten sam skrypt co `python scripts/gen_local_https_cert.py` z katalogu głównego projektu).

Powstaną **`certs/dev.crt`** i **`certs/dev.key`**. Dopiero wtedy **Server** wstanie na **`https://127.0.0.1:8000`**.

**Klient** domyślnie łączy się pod ten sam adres. Biblioteka HTTP (`requests`) przy HTTPS **sprawdza certyfikat serwera**. Żeby uznać nasz **lokalny** cert (self-signed), podajemy jej ścieżkę do **tego samego** pliku `certs/dev.crt` — wtedy połączenie jest szyfrowane i klient nie krzyczy „nieznany certyfikat”. To nie jest żadne „wyłączanie zabezpieczeń”; po prostu mówimy klientowi: „ufaj dokładnie temu plikowi z repo”.

`package_url` w manifeście może nadal pokazywać `http://…` — adres pobrania paczki jest **dopasowywany** do `UPDATE_SERVER_URL`, chyba że ustawisz `UPDATE_USE_RAW_PACKAGE_URL=true`.

**Signing Machine** zostaje na **`http://127.0.0.1:9000`** (tylko komunikacja między procesami na jednym komputerze).

### Jeśli **nie** wygenerujesz certów HTTPS

To **nie blokuje** generowania kluczy root/signing (YubiKey mock, Keygen) — te są od **podpisów**, nie od TLS.

Natomiast bez `certs/dev.crt` i `certs/dev.key`:

- **Server** od razu się wyłączy i w konsoli wypisze ramkę **„STOP: brak certyfikatów HTTPS”**.
- **Client** przy adresie `https://…` zatrzyma się na początku z komunikatem **„STOP: brak pliku certyfikatu pod HTTPS”**.

---

## Uruchomienie od zera

### 0. Certyfikat HTTPS (jednorazowo na czystym repo)

Uruchom **„Gen Local HTTPS Cert”** (albo `python scripts/gen_local_https_cert.py` z katalogu projektu).

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

## Instrukcja startu — **działa** vs **widać że jest źle**

### A) Żeby **normalnie działało**

Wykonaj po kolei (nowe okno Run / terminal dla procesów, które mają wisieć w tle):

| Kolejność | Co uruchomić | Uwaga |
|-----------|----------------|--------|
| 1 | **Gen Local HTTPS Cert** | Powstaną `certs/dev.crt` i `certs/dev.key`. Bez tego Server i Client na HTTPS się nie dogadają. |
| 2 | **YubiKey mock** → Keygen (1) | Hex do `client/src/config.py`. |
| 3 | **Keygen** (signing machine) | Hasło → opcjonalnie `SIGNING_KEY_PASSWORD` przy Signing Machine. |
| 4 | **YubiKey mock** → Certify (2) | `keys/signing_cert.json`. |
| 5 | **Signing Machine** | Zostaw włączone (`http://127.0.0.1:9000`). |
| 6 | **Server** | Zostaw włączone (`https://127.0.0.1:8000`). |
| 7 | **Client** | Np. `--local-version 0.0.1` jeśli chcesz zobaczyć pobranie paczki (wersja z manifeście wyższa). |

**Sukces:** w logu klienta kolejno certyfikat OK → podpisy manifestu OK → przy update: pobranie ZIP i zgodny hash.

---

### B) Żeby **zobaczyć, że coś jest nie tak** (świadomie psujemy jeden warunek)

| Co pominąć / zepsuć | Co powinieneś zobaczyć |
|---------------------|-------------------------|
| Nie robisz **Gen Local HTTPS Cert** (usuń lub nie twórz `certs/dev.*`) i odpalasz **Server** | W konsoli ramka **„STOP: brak certyfikatów HTTPS”**, proces się kończy (nie ma nasłuchu). |
| To samo brak `dev.crt`, ale odpalasz **Client** na `https://…` | Na początku ramka **„STOP: brak pliku certyfikatu pod HTTPS”**, klient kończy zanim pobierze manifest. |
| **Signing Machine** wyłączona, a **Server** startuje | W logu Servera ostrzeżenie/błąd o braku świeżego podpisu / unreachable signing machine — serwer może wstać, ale bez poprawnych sygnatur aktualizacja nie przejdzie weryfikacji po stronie klienta. |
| Klient z `--local-version` **wyższą lub równą** niż w manifeście | Komunikat w stylu „No update required” / brak pobierania — to **poprawne** zachowanie, nie błąd. |

---

## Po tygodniu (rotacja kluczy)

Powtórz kroki **2 → 3** (nowe klucze signing machine + nowy certyfikat). Kroki 1 i edycja `config.py` nie są potrzebne.
