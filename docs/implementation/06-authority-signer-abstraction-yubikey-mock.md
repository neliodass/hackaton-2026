# Task 06 — Abstrakcja `AuthoritySigner` + mock YubiKey / HSM

## Cel

Oddzielić **operację podpisu** authority od reszty kodu tak, aby:

- w **CI i testach** używać deterministycznego mocka (bez sprzętu),
- w **demo** używać pliku PEM (jak prototyp),
- w **staging** symulować YubiKey (opóźnienie, PIN, log audytu),
- w **prod** podłączyć PKCS#11 lub zewnętrzny podpis.

To jest **główny task jakościowy** względem wersji badawczej.

## Interfejs (Protocol / ABC)

```python
# qrbt/authority/signer.py
from typing import Protocol, runtime_checkable

@runtime_checkable
class AuthoritySigner(Protocol):
    """Podpisuje cert_payload bajty — zwraca sygnaturę Ed25519 (raw 64 bytes)."""

    def sign_cert_payload(self, cert_payload: bytes) -> bytes: ...

    def public_key_pem(self) -> str:
        """SPKI PEM — do exportu dla klientów i testów spójności."""
```

Opcjonalnie drugi protocol dla init (generowanie pary tylko w dev):

```python
class AuthorityKeyGenerator(Protocol):
    def generate_and_persist(self) -> str: ...  # zwraca pub PEM
```

## Implementacja A — `FileAuthoritySigner` (zamiennik prototypu)

- Konstruktor: `keys_path: Path`, odczyt `authority.priv` z JSON lub osobny `authority.pem`.
- `sign_cert_payload`: `cryptography` Ed25519 `sign()`.
- Użycie: `rotate_ephemeral` i ewentualnie `init` (generacja).

## Implementacja B — `InjectedSignatureSigner` (podpis z zewnątrz / YubiKey „ręcznie”)

- Konstruktor: tylko `public_key_pem` (known good).
- `sign_cert_payload`: **nie** — ta klasa nie podpisuje; zamiast tego workflow CLI:

  1. `qrbt-server rotate-ephemeral --print-cert-payload-b64` wypisuje base64 `cert_payload`.
  2. Operator podpisuje offline, wpisuje `qrbt-server rotate-ephemeral --cert-sig-hex ...`.

To omija potrzebę biblioteki PKCS#11 w Pythonie na pierwszym etapie.

## Implementacja C — `MockYubiKeySigner` (zalecane dla testów i „lepszego” dema)

**Cel mocka:** zachowanie jak HSM: *klucz prywatny nie jest serializowany do JSON*, jest trzymany w pamięci obiektu lub w pliku tymczasowym z chmod 600, a interfejs udaje **PIN** i **latency**.

### Zachowanie

| Aspekt | Implementacja |
|--------|----------------|
| Klucz | `Ed25519PrivateKey.generate()` przy `MockYubiKeyState.bootstrap()` albo wczytanie z `QRBT_MOCK_YUBIKEY_SEED` (np. 32 bajty → deterministyczny klucz przez HKDF lub bezpośrednio jako seed do libsodium — prościej: zapisać PEM w `tmpdir` fixture). |
| PIN | Env `QRBT_MOCK_YUBIKEY_PIN` (default `"123456"`). Przed `sign_cert_payload` sprawdź `unlock(pin)` albo pierwszy sign rzuca `YubiKeyLockedError`. |
| Opóźnienie | `time.sleep(float(os.environ.get("QRBT_MOCK_YUBIKEY_LATENCY_MS", 0)) / 1000)` — testy mogą ustawić 0. |
| Licznik operacji | Atrybut `_sign_count` — asercje w testach „tylko jeden podpis na rotację”. |
| Audyt | Logger `logging.getLogger("qrbt.mock_yubikey").info("sign_cert_payload bytes=%d", len(payload))` — bez treści payloadu w prod log. |

### Przykładowa szkieletowa klasa

```python
class MockYubiKeySigner:
    def __init__(self, pin: str | None = None):
        self._pin_ok = False
        self._pin = pin or os.environ.get("QRBT_MOCK_YUBIKEY_PIN", "123456")
        self._sk = Ed25519PrivateKey.generate()
        self._sign_count = 0

    def unlock(self, pin: str) -> None:
        if pin != self._pin:
            raise ValueError("bad pin")
        self._pin_ok = True

    def sign_cert_payload(self, cert_payload: bytes) -> bytes:
        if not self._pin_ok:
            raise RuntimeError("mock yubikey locked")
        self._sign_count += 1
        return self._sk.sign(cert_payload)

    def public_key_pem(self) -> str:
        ...
```

### Fixture pytest

```python
@pytest.fixture
def yubi(mock_pin):
    y = MockYubiKeySigner(pin=mock_pin)
    y.unlock(mock_pin)
    return y
```

Test integracyjny: pełny `rotate_ephemeral` z `AuthoritySigner=y` → manifest ma poprawny `ephemeral_cert_sig_ed`.

## Implementacja D — `SubprocessYubiKeySigner` (opcjonalnie, bliżej prawdy)

- Wywołanie `ykman piv keys sign` lub małego wrappera w Go/Rust — **poza zakresem** minimalnego taska; opisz w README jako future work.
- Kontrakt: stdin = raw `cert_payload`, stdout = binarna sygnatura 64 B.

## Wiring w CLI `rotate-ephemeral`

1. Fabryka `get_signer() -> AuthoritySigner` czyta `QRBT_AUTHORITY_BACKEND`:

   - `file` → `FileAuthoritySigner`
   - `mock_yubikey` → `MockYubiKeySigner` (+ wymuszenie `unlock` w interaktywnym CLI: `click.prompt("PIN", hide_input=True)`)

2. Po wygenerowaniu nowych ephemeral:

   - `cert_payload = build_cert_payload(...)`
   - `sig = signer.sign_cert_payload(cert_payload).hex()`
   - zapis do `keys.json` → `ephemeral.cert_sig_ed`

3. **`authority.priv` nie jest wymagany** gdy backend = `mock_yubikey` lub zewnętrzny inject — wtedy `init` zapisuje tylko `authority.pub` (z mocka) albo pub jest importowany z pliku.

## Kryteria ukończenia

- [ ] Jeden test: `MockYubiKeySigner` + `rotate_ephemeral` + weryfikacja manifestu przez funkcję z taska 05.
- [ ] Drugi test: `sign_cert_payload` bez `unlock` → wyjątek.
- [ ] Trzeci test: zły PIN → wyjątek.
- [ ] Dokumentacja env vars w `README` nowego repo.

## Dlaczego to jest „lepsze mockowanie YubiKey”

| Prototyp | Ten task |
|----------|----------|
| `authority_priv` zawsze w `keys.json` | Prywatny klucz za interfejsem; mock z PIN + lock |
| Brak symulacji opóźnienia / audytu | Konfigurowalne zachowania jak przy tokenie |
| Niemożliwe podmienienie w teście | Dependency injection `AuthoritySigner` |
