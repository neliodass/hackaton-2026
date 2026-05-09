# Secure Software Update System – instrukcje setupu projektu dla agenta

## Kontekst projektu

System składa się z dwóch komponentów:

- **Update Client** – aplikacja desktopowa cross-platform (Windows + Linux), Python + Tkinter GUI
- **Update Server** – serwer aktualizacji, Python, interfejs CLI, bez GUI

Oba komponenty komunikują się przez HTTPS. Projekt jest realizowany w ramach konkursu Kościuszkon 2026, temat Honeywell #1 – Secure Software Update System.

---

## Struktura repozytorium

```
secure-update-system/
│
├── client/                        # Aplikacja kliencka
│   ├── src/
│   │   ├── gui/                   # Moduły Tkinter (widoki, komponenty)
│   │   ├── core/                  # Logika aktualizacji (pobieranie, weryfikacja)
│   │   ├── crypto/                # Weryfikacja podpisów, hashing
│   │   └── main.py                # Entry point klienta
│   ├── tests/
│   ├── requirements.txt
│   └── README.md
│
├── server/
│   ├── src/
│   │   ├── api/                   # Endpointy HTTP
│   │   ├── storage/               # Obsługa paczek i manifestów
│   │   ├── crypto/                # Podpisywanie paczek
│   │   └── main.py                # Entry point serwera (CLI)
│   ├── packages/                  # Katalog przechowywanych paczek aktualizacji
│   ├── tests/
│   ├── requirements.txt
│   └── README.md
│
├── shared/                        # Opcjonalnie: wspólne struktury danych / schematy
│   └── schemas/                   # JSON Schema manifestu aktualizacji
│
├── keys/                          # Klucze do podpisywania (NIE commitować kluczy prywatnych)
│   ├── .gitignore                 # Wyklucza *.pem, *.key, private/
│   └── README.md                  # Instrukcja generowania kluczy
│
├── docs/
│   ├── architecture.md
│   ├── threat_model.md
│   └── security_analysis.md
│
├── .gitignore
├── README.md
└── Makefile                       # Opcjonalnie: skróty do uruchamiania obu komponentów
```

---

## Wymagania środowiskowe

### Wersja Pythona

Oba komponenty wymagają **Python 3.10 lub nowszego**. Agent powinien sprawdzić dostępną wersję przed inicjalizacją projektu.

### Wirtualne środowiska

Każdy komponent (client, server) ma **osobne** wirtualne środowisko (`venv`). Nie używać wspólnego środowiska dla obu.

```
client/venv/
server/venv/
```

Środowiska nie są commitowane do repozytorium – muszą znaleźć się w `.gitignore`.

---

## Zależności – Update Client

Plik: `client/requirements.txt`

Wymagane biblioteki:

| Biblioteka | Cel |
|---|---|
| `cryptography` | Weryfikacja podpisów Ed25519, hashing |
| `requests` | Żądania HTTP do serwera aktualizacji |
| `tkinter` | Wbudowany w Python – nie instalować przez pip, sprawdzić dostępność |
| `certifi` | Aktualne certyfikaty CA dla weryfikacji TLS |
| `packaging` | Porównywanie wersji semantycznych (SemVer) |

Opcjonalne (stretch goals):

| Biblioteka | Cel |
|---|---|
| `python-tpm2-pytss` | Integracja z TPM 2.0 (opcjonalnie) |
| `PyYubiKey` lub `yubikey-manager` | Integracja z YubiKey (opcjonalnie) |

**Uwaga dla agenta:** Tkinter jest częścią standardowej biblioteki Pythona, ale na niektórych dystrybucjach Linuxa wymaga osobnej instalacji systemowej (`python3-tk`). Agent powinien to odnotować w README klienta.

---

## Zależności – Update Server

Plik: `server/requirements.txt`

Wymagane biblioteki:

| Biblioteka | Cel |
|---|---|
| `Flask` lub `FastAPI` | Framework HTTP serwera aktualizacji |
| `cryptography` | Generowanie i obsługa kluczy Ed25519, podpisywanie paczek |
| `click` | Budowanie interfejsu CLI serwera |
| `uvicorn` | Serwer ASGI (jeśli wybrano FastAPI) |
| `pydantic` | Walidacja danych manifestu (jeśli FastAPI) |

**Uwaga dla agenta:** Wybór między Flask a FastAPI należy podjąć przed inicjalizacją projektu. FastAPI jest preferowane ze względu na automatyczną walidację i dokumentację, Flask jeśli priorytetem jest prostota.

---

## Inicjalizacja repozytorium Git

Agent powinien wykonać następujące kroki:

1. Zainicjować repozytorium: `git init`
2. Ustawić domyślną gałąź na `main`
3. Utworzyć plik `.gitignore` obejmujący co najmniej:
   - `venv/`, `__pycache__/`, `*.pyc`, `*.pyo`
   - `*.pem`, `*.key`, `*.p8` – klucze kryptograficzne
   - `server/packages/*.bin`, `server/packages/*.zip` – binarne paczki aktualizacji (opcjonalnie, zależnie od rozmiaru)
   - `.env`, `config.local.*` – pliki z lokalną konfiguracją
   - `dist/`, `build/`, `*.egg-info/`
4. Wykonać pierwszy commit z samą strukturą katalogów i plikami `.gitkeep`

---

## Manifest aktualizacji – format JSON

Serwer udostępnia manifest w formacie JSON. Agent powinien zaimplementować obsługę następującej struktury:

```json
{
  "version": "2.5.0",
  "release_date": "2026-05-09T10:00:00Z",
  "package_filename": "secureapp-2.5.0.bin",
  "package_size_bytes": 14876432,
  "sha256": "<hex string>",
  "signature_base64": "<Ed25519 signature over sha256, base64-encoded>",
  "min_required_version": "2.0.0",
  "changelog_url": "https://update.example.com/changelog/2.5.0"
}
```

Plik JSON Schema dla manifestu powinien znaleźć się w `shared/schemas/manifest.schema.json`.

---

## Endpointy serwera

Agent powinien zaimplementować następujące endpointy HTTP:

| Metoda | Ścieżka | Opis |
|---|---|---|
| `GET` | `/v1/latest` | Zwraca manifest najnowszej wersji (JSON) |
| `GET` | `/v1/packages/{filename}` | Pobieranie paczki binarnej |
| `GET` | `/v1/pubkey` | Zwraca klucz publiczny serwera (PEM) |
| `GET` | `/health` | Health check serwera |

Wszystkie endpointy poza `/health` powinny wymagać połączenia HTTPS w produkcji. Na potrzeby developmentu dopuszczalne jest HTTP z wyraźną flagą `--dev` w CLI.

---

## Interfejs CLI serwera

Serwer uruchamiany jest z linii poleceń. Agent powinien zaimplementować następujące komendy przez `click`:

```
python src/main.py start              # Uruchomienie serwera HTTP
python src/main.py keygen             # Generowanie pary kluczy Ed25519
python src/main.py sign <plik>        # Podpisanie paczki aktualizacji kluczem prywatnym
python src/main.py add-package <plik> # Dodanie podpisanej paczki do serwera
python src/main.py list-packages      # Lista dostępnych paczek
```

Opcje globalne:

```
--host TEXT       Adres nasłuchu (domyślnie: 0.0.0.0)
--port INTEGER    Port (domyślnie: 8443)
--dev             Tryb deweloperski (HTTP zamiast HTTPS, verbose logi)
--keyfile PATH    Ścieżka do klucza prywatnego
```

---

## Przepływ kryptograficzny – wytyczne dla agenta

Agent implementuje kryptografię wyłącznie przez bibliotekę `cryptography` (PyCA). Nie używać `pycrypto`, `pycryptodome` ani wbudowanego modułu `ssl` do operacji kryptograficznych.

### Generowanie kluczy (serwer)

- Algorytm: **Ed25519**
- Klucz prywatny zapisywany w formacie PEM, zabezpieczony hasłem (`BestAvailableEncryption`)
- Klucz publiczny zapisywany w formacie PEM bez hasła
- Katalog `keys/private/` wykluczony z repozytorium przez `.gitignore`

### Podpisywanie paczki (serwer)

1. Oblicz SHA-256 pliku paczki
2. Podpisz bajty SHA-256 (hex string zakodowany UTF-8) kluczem prywatnym Ed25519
3. Zakoduj podpis do Base64
4. Umieść hash i podpis w manifeście JSON

### Weryfikacja paczki (klient)

1. Pobierz manifest przez HTTPS
2. Pobierz klucz publiczny serwera przez `/v1/pubkey`
3. Pobierz plik paczki
4. Oblicz SHA-256 pobranej paczki – porównaj z polem `sha256` w manifeście
5. Zdekoduj `signature_base64` z Base64
6. Zweryfikuj podpis Ed25519 nad bajty SHA-256 (hex string UTF-8)
7. Sprawdź czy `version` z manifestu jest wyższa niż zainstalowana (antydowngrade)
8. Jeśli wszystkie kroki przeszły – paczka jest autentyczna i nienaruszona

---

## Struktura GUI klienta (Tkinter)

Agent powinien zorganizować GUI jako oddzielne klasy/moduły w `client/src/gui/`:

| Plik | Zawartość |
|---|---|
| `app.py` | Główna klasa aplikacji, inicjalizacja okna `Tk`, routing między widokami |
| `dashboard.py` | Widok główny: status, dostępne aktualizacje, przycisk sprawdzania |
| `update_progress.py` | Widok postępu: pasek, etapy, logi w czasie rzeczywistym |
| `verification_details.py` | Widok wyników weryfikacji kryptograficznej |
| `history.py` | Historia zainstalowanych aktualizacji |
| `settings.py` | Formularz ustawień klienta |
| `audit_log.py` | Widok dziennika zdarzeń |
| `components.py` | Współdzielone komponenty: StatusBadge, StepIndicator, MonoLabel |

Nawigacja między widokami przez mechanizm `tkraise()` lub podmianę ramki (`Frame`) – bez zewnętrznych bibliotek routingu.

**Uwaga dla agenta:** Operacje sieciowe (pobieranie, weryfikacja) muszą być wykonywane w osobnych wątkach (`threading.Thread`) żeby nie blokować pętli zdarzeń Tkinter. Wyniki przekazywać do GUI przez `widget.after()`.

---

## Konfiguracja klienta

Klient przechowuje konfigurację w pliku `config.json` w katalogu użytkownika:

- Windows: `%APPDATA%\SecureUpdateClient\config.json`
- Linux: `~/.config/secure-update-client/config.json`

Domyślna konfiguracja:

```json
{
  "server_url": "https://localhost:8443",
  "check_interval_hours": 24,
  "auto_install": false,
  "trusted_pubkey_path": null,
  "temp_download_dir": null
}
```

---

## Testy

Agent powinien przygotować szkielety testów w katalogach `client/tests/` i `server/tests/` używając `pytest`.

Minimalny zakres testów:

**Serwer:**
- Generowanie i wczytywanie kluczy Ed25519
- Podpisywanie paczki i poprawność podpisu
- Endpoint `/v1/latest` zwraca poprawny JSON
- Endpoint `/v1/packages/{filename}` zwraca plik lub 404

**Klient:**
- Weryfikacja poprawnego podpisu (`True`)
- Weryfikacja niepoprawnego podpisu (`False`)
- Wykrywanie niezgodności SHA-256
- Wykrywanie próby downgrade
- Poprawne parsowanie manifestu JSON

---

## Plik README główny repozytorium

Agent powinien wygenerować `README.md` zawierający:

1. Krótki opis projektu (2–3 zdania)
2. Schemat architektury (ASCII lub opis tekstowy)
3. Wymagania systemowe (Python 3.10+, system operacyjny)
4. Instrukcja szybkiego startu:
   - Klonowanie repozytorium
   - Setup środowisk wirtualnych
   - Generowanie kluczy (`keygen`)
   - Uruchomienie serwera
   - Uruchomienie klienta
5. Krótki opis przepływu bezpieczeństwa
6. Informacja o tym co jest poza zakresem MVP (TPM, YubiKey)

---

## Narzędzia bezpieczeństwa – analiza statyczna

### Bandit – analiza bezpieczeństwa kodu Python

**Kiedy używać:** za każdym razem gdy dodajesz nową bibliotekę do projektu lub integrujesz zewnętrzny moduł. Bandit wykrywa typowe podatności w kodzie Pythona (hardcoded secrets, niebezpieczne wywołania, problemy z kryptografią).

**Jak uruchomić:**

```bash
# Skanowanie całego projektu
bandit -r server/src/ client/src/

# Skanowanie tylko serwera
bandit -r server/src/

# Skanowanie tylko klienta
bandit -r client/src/

# Raport w formacie JSON
bandit -r server/src/ client/src/ -f json -o bandit-report.json
```

**Interpretacja wyników:**
- `HIGH severity` – należy naprawić przed mergem
- `MEDIUM severity` – należy ocenić i udokumentować wyjątek jeśli akceptowalny
- `LOW severity` – informacyjne, można pominąć jeśli świadomie

---

### Semgrep – analiza wzorców i reguł bezpieczeństwa

**Kiedy używać:** przy każdym pushowaniu nowego featura (przed otwarciem PR lub przed mergem do `main`). Semgrep sprawdza kod pod kątem znanych wzorców podatności oraz wymuszonych reguł projektu.

**Jak uruchomić:**

```bash
# Skanowanie z domyślnym zestawem reguł bezpieczeństwa Python
semgrep --config=p/python server/src/ client/src/

# Reguły specyficzne dla kryptografii
semgrep --config=p/cryptography server/src/ client/src/

# Reguły OWASP
semgrep --config=p/owasp-top-ten server/src/ client/src/

# Skanowanie całego projektu, wszystkie reguły naraz
semgrep --config=p/python --config=p/cryptography server/src/ client/src/

# Raport JSON
semgrep --config=p/python server/src/ client/src/ --json -o semgrep-report.json
```

**Uwaga dla agenta:** Semgrep wymaga konta (bezpłatne) do pobierania reguł z registry (`p/...`). Alternatywnie można użyć reguł lokalnych lub `--config=auto` dla automatycznego doboru reguł bez logowania.

---

## Czego agent nie powinien robić

- Nie commitować żadnych kluczy prywatnych ani pliku `.env` z sekretami
- Nie implementować własnych algorytmów kryptograficznych – używać wyłącznie biblioteki `cryptography`
- Nie używać `pickle` do serializacji danych przesyłanych między klientem a serwerem
- Nie wyłączać weryfikacji TLS (`verify=False` w `requests`) poza trybem `--dev`
- Nie mieszać logiki GUI z logiką kryptograficzną – zachować separację warstw
- Nie używać `eval()` ani `exec()` na danych pochodzących z serwera
