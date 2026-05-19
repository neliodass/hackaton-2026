# UPDT Secure

Monorepo dla projektu konkursowego Kościuszkon 2026 (Honeywell #1).

Prezentacja PowerPoint: [Prezentacja](MiśkaLubidotNet.pptx)

## Opis
**UPDT Secure** to narzędzie pozwalające na bezpieczne dostarczanie aktualizacji oprogramowania do użytkowników końcowych. 
Składa się z trzech głównych elementów: serwera dystrybucji (udostępnia manifesty i pakiety), klienta desktopowego (interfejs graficzny i 
wiersz poleceń) oraz serwisu certyfikującego (odpowiedzialnego za zaufaną tożsamość podmiotu, który autoryzuje wydania).

Projekt adresuje sytuację, w której atakujący może wpływać na sieć, podszywać się pod infrastrukturę lub dążyć do kompromitacji materiałów 
kryptograficznych używanych przy update’ach. Modeluje zagrożenia typowe dla rzeczywistych łańcuchów dystrybucji: podsłuch i podmiana ruchu (MITM), 
fałszywe lub zmodyfikowane binaria, wymuszenie instalacji starszej wersji z lukami bezpieczeństwa (rollback), freeze attacks (utrzymywanie użytkownika 
na przestarzałym „najnowszym” updacie) oraz scenariusze celowanego ataku na supply chain.

Klient weryfikuje spójność i autentyczność każdego wydania w oparciu o jawnie zdefiniowany łańcuch zaufania - od kluczy zaufania osadzonych po stronie klienta, 
przez certyfikowany okres ważności uprawnień podmiotu podpisującego, aż po kryptograficzne dowody powiązania manifestu z konkretnym pakietem. Ważną rolę pełnią 
też mechanizmy transparentności jak Transparency Log, które utrudniają ciche wprowadzanie update’ów do poszczególnych użytkowników lub cofanie wersji bez 
pozostawienia śladu w modelu zagrożeń projektu.

Aplikacja działa zarówno na Windowsie, jak i na Linuxie, korzysta z Hardware Security Module i symuluje użycie TPM.

<img width="1188" height="862" alt="serwer_new_update" src="https://github.com/user-attachments/assets/16ddd94f-0dfb-456c-a3a3-34668b44061c" />

<img width="1188" height="862" alt="client_update_download" src="https://github.com/user-attachments/assets/87914846-983c-4718-9954-c5c89ab4d986" />

## Jakie są główne ataki/problemy na jakie jest narażona nasza aplikacja?

- **Tampering** — atakujący modyfikuje paczkę update'u w transporcie albo na serwerze. Zapobieganie: “SHA-256 hash” paczki jest częścią podpisanego manifestu, a klient liczy hash pobranego pliku i porównuje.
- **Forgery** — atakujący próbuje wyprodukować własny "official update". Zapobieganie: podpis Ed25519 manifestu za pomocą klucza, którego atakujący nie ma. Klient weryfikuje kluczem publicznym (który jest embedded).
- **MITM** — atakujący przechwytuje ruch sieciowy. Zapobieganie warstwowe: HTTPS na transport + podpisy niezależne od TLS. Te dwie rzeczy razem, bo sam TLS to za mało, gdyż skompromitowany serwer też korzysta z TLS.
- **Downgrade / rollback** — atakujący serwuje starą, ważnie podpisaną wersję z luką (kiedyś wydaliśmy update, który był dobrze podpisany, zweryfikowany itp., ale miał lukę. Ktoś chce wgrać ten stary update, żeby wykorzystać lukę). Obrona: klient pamięta swoją aktualną wersję i odrzuca manifesty z wersją niższą lub równą.
- **Freeze attack** — atakujący serwuje stary, legalnie podpisany manifest w nieskończoność, blokując dostarczenie patcha bezpieczeństwa (spami starym updatem). Obrona: pole released_at w manifeście, klient odrzuca manifesty starsze niż próg (np. 30 dni).
- **Compromised update server** — serwer zostaje zhakowany. Obrona: klucz prywatny nie żyje na serwerze, więc atakujący nie może wyprodukować ważnych podpisów. Rzeczy na serwerze są już podpisane, a nie serwer je podpisuje, innymi  słowy - serwer tylko trzyma rzeczy, a nie je weryfikuje. Może najwyżej serwować stare legalne pliki — ale to łapią mechanizmy powyżej.
- **Corrupted state** — update przerywa się w połowie (brak prądu, brak miejsca). Obrona: pobieranie do pliku tymczasowego, weryfikacja przed rename, atomic apply.

## Zaimplementowane mechanizmy
- **Asymetryczna kryptografia**, hybrydowe podpisy cyfrowe za pomocą algorytmu klasycznego Ed25519 oraz algorytmu Post Quantum Cryptography ML-DSA-65 do weryfikacji tożsamości nadawcy,
- **Hardware Security Module** - fizyczny YubiKey trzymany offline. Używany rzadko, do podpisywania kluczy efemerycznych,
- **Klucze efemeryczne**, wymieniane co określony czas, aby zapobiegać przyszłym atakom “harvest now, decrypt later” i łagodzić efekty wycieku klucza,
- **Hash functions** (SHA-256) do weryfikacji integralności update’ów,
- **Certyfikaty z czasem ważności** aby uniknąć m.in. ataków downgrade i freeze,
- **Weryfikacja łańcucha certyfikatów**,
- **Kanonizacja json**,
- **Self-monitoring** własnych wpisów,
- **Transparency log** do wykrywania udanych breachy systemu i ataków targeted supply chain,
- Zapobieganie rollbackom dzięki **weryfikacji wersji update’u** przy pomocy **monotonic counteru TPMu**,
- Bezpieczeczny transfer danych dzięki użyciu zarówno **HTTPS**, jak i **TLS**,
- Aplikacja przetestowana i działająca na **Windowsie i Linuxie**,
- Weryfikacja kodu aplikacji testami **SAST** i **SCA** za pomocą **SonarQube**,
- Ciągła weryfikacja poprawnego działania kodu za pomocą **testów symulujących różne ataki i breache**, zautomatyzowanych przy pomocy Github Actions,
- **Software Bill of Materials (SBOM)** -  dokładny spis wszystkich komponentów, bibliotek i zależności wchodzących w skład kodu aplikacji.

---

## Koncepty ulepszenia projektu w przyszłości
- Możliwość wymiany algorytmu root w przyszłości na bardziej “quantum proof” - w naszej apce prawie że już wykonywalne
- Transparency log - Gossiping (klienci wymieniają się między sobą informacjami o stanie loga) lub Witnesses (kilka bytów, np. firm, organizacji, regularnie pobiera loga i co-signuje go, potwierdzając jego autentyczność. Update przechodzi tylko, jeśli m z n klientów potwierdzi log),
- Yubi-key - Użyć kilku kluczy, z których np. 3 na 5 muszą się zgadzać. Najważniejsze osoby odpowiedzialne za produkcję otrzymują po jednym.
- Stage rollouts - 1% klientów dostaje update pierwszego dnia. Jeśli telemetria pokazuje potwierdza powodzenie, 10% drugiego dnia. Etc. Manifesty mogą zawierać rollout_percentage.
- Klient nie tylko weryfikuje podpis - weryfikuje też, że build został zrobiony w zaufanym środowisku. Build server używa TEE (Trusted Execution Environment) (to dość świeży koncept).

---

## Struktura

- `client/` – Update Client (Python + Tkinter)
- `server/` – Update Server (FastAPI)
- `signing_machine/` – Signing Machine (FastAPI)
- `yubikey_mock/` – Mock sprzętowego klucza YubiKey
- `keys/` – materiały kryptograficzne (klucze prywatne wykluczone z repo)
- `certs/` – lokalne pliki TLS (generowane, nie commituj); `scripts/gen_local_https_cert.py`
- `scripts/` – m.in. generowanie certu pod **HTTPS tylko na 127.0.0.1** (pokaz, bez domeny)

---

## Uruchomienie od zera

### 0. Certyfikat HTTPS (jednorazowo na czystym repo)

Uruchom **„Gen Local HTTPS Cert”** (albo `python scripts/gen_local_https_cert.py` z katalogu projektu).

### 1. Keygen

Generuje klucze signing machine. Na pytanie o hasło naciśnij Enter (bez hasła) lub wpisz hasło.

Jeśli ustawiłeś hasło, wpisz je też w run configu **Signing Machine** jako zmienną środowiskową `SIGNING_KEY_PASSWORD`.

---

### 2. YubiKey → opcja `1 Keygen`

Generuje parę kluczy root (Ed25519 + ML-DSA). Na pytanie o PIN naciśnij Enter (bez PINu) lub wpisz hasło.

Po zakończeniu skopiuj wygenerowane klucze publiczne do `client/src/config.py`:
- zawartość `keys/root/root_ed25519_pub.hex` → `EMBEDDED_ROOT_PUBLIC_KEY`
- zawartość `keys/root/root_mldsa_pub.hex` → `EMBEDDED_ROOT_PQ_PUBLIC_KEY_HEX`

---

### 3. YubiKey → opcja `2 Certify`

Ceremonia podpisania certyfikatu — root key autoryzuje signing machine na 7 dni.

- PIN YubiKey'a: ten sam co w kroku 2
- Hasło signing machine: ten sam co w kroku 1
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
