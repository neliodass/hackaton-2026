# Task 10 — TPM mock i polityka wersji (anti-rollback)

## Cel

Zastąpić prototypowe `version <= tpm` (porównanie stringów) **świadomą polityką** albo udokumentować ograniczenie.

## Plik stanu (jak w prototypie)

- Ścieżka: `~/.qrbt_tpm.json`
- Zawartość: `{"version": "1.0.0"}` (semver lub dowolny string — **ustal w tasku 00**).

## Opcja A — semver strict (zalecane w „lepszym” repo)

- Zależność: `packaging.version.Version` lub `semver` package.
- Reguła instalacji: `new_version > installed_version` (strict), w przeciwnym razie „No update” lub „Blocked downgrade”.

## Opcja B — zachowanie prototypu

- Lexykograficzne `<=` na stringach — OK tylko dla `0.0.0`, `1.0.0`, `1.1.0` bez `1.10.0`.

## Interfejs modułu

```python
def tpm_read_version(path: Path = DEFAULT_TPM_PATH) -> str: ...
def tpm_write_version(version: str, path: Path = ...) -> None: ...
def may_install(new_version: str, installed: str) -> bool: ...
```

## Kryteria ukończenia

- [ ] Test: `1.10.0` vs `1.9.0` — semver wygrywa; stringowy prototyp opisz jako failing test (skipped lub xfail) jeśli zostajesz przy stringu.

## Pułapki

- TPM mock na pliku — każdy proces użytkownika może go edytować; w `SECURITY.md` napisz, że to **nie** ochrona przed malware na tym samym koncie.
