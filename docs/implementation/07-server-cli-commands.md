# Task 07 — CLI serwera (`init`, `rotate-ephemeral`, `add-release`, `serve`)

## Cel

Zaimplementować polecenia Click (lub Typer) o zachowaniu zgodnym z prototypem, ale z **wywołaniem** modułów z tasków 03–06.

## `init`

1. `ensure_dirs()` — tworzy `server_data/manifests`, pusty `log.json` jeśli brak.
2. Jeśli `keys.json` istnieje → `click.confirm` nadpisanie.
3. Backend authority:
   - `file`: generuj `Ed25519PrivateKey.generate()`, zapisz `priv`+`pub` w JSON.
   - `mock_yubikey`: generuj `MockYubiKeySigner`, zapisz **tylko** `authority.pub` (PEM string) + metadata `authority_backend: mock_yubikey` (pole opcjonalne dla czytelności).
4. Komunikat ostrzegawczy o przechowywaniu klucza.

## `rotate-ephemeral --days N`

1. `ensure_dirs()`.
2. Wczytaj `keys.json`; musi być `authority` z możliwością podpisu (plik lub unlocked mock).
3. Generuj nowe ephemeral Ed25519 + ML-DSA-65 (`ML_DSA_65.keygen()`).
4. `cert_payload = build_cert_payload(eph_pub_pem, eph_pqc_pub_hex)`.
5. `cert_sig_ed = hex(signer.sign_cert_payload(cert_payload))`.
6. Zapisz pliki `.pem` / `.hex` ephemeral.
7. Uaktualnij `keys.json`: `ephemeral.{cert_sig_ed, issued_at, expires_at}` gdzie `expires_at = now + days*86400`.

**Błędy:**

- Brak `ephemeral` przy pierwszym uruchomieniu — OK, tworzysz od zera.
- Mock bez unlock — komunikat „odblokuj token (PIN)”.

## `add-release --version --notes [--file]`

1. `get_current_ephemeral_keys()`:
   - brak sekcji `ephemeral` → błąd z instrukcją `rotate-ephemeral`.
   - `now >= expires_at` → błąd wygaśnięcia.
   - brak plików `.pem`/`.hex` → błąd.
2. Przygotuj binarkę (plik użytkownika lub sample bytes jak w prototypie).
3. Zbuduj manifest, podpisz (task 05), `add_manifest` + kopiuj `.bin`.

## `serve --host --port`

1. `ensure_dirs()`.
2. Montowanie opcjonalne `/static` → katalog manifestów (jak prototyp).
3. `uvicorn.run("qrbt.server.app:app", ...)` **albo** `uvicorn qrbt.server.app:create_app` factory.

## Kryteria ukończenia

- [ ] `test.sh` analog: init → rotate → dwa add-release → serwer w tle → klient.
- [ ] Zły exit code przy błędzie (np. 1).

## Pułapki

- Import path: `uvicorn.run('package.module:app')` wymaga poprawnego `PYTHONPATH` / instalacji editable (`pip install -e .`).
