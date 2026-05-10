# Task 01 — Model zagrożeń i granice zaufania

## Cel

Zanim napiszesz kod, zamroź **co system ma chronić**, przed czym **nie chroni** (bez TLS, bez prawdziwego TPM), i **kto jest TCB** (trusted computing base).

## Zaufane komponenty (TCB)

1. **Klient** z poprawnie wdrożonym `authority_pub.pem` (root public).
2. **Implementacja krypto** (`cryptography`, `dilithium-py`) — zakładamy brak błędów w bibliotekach.
3. **Serwer aktualizacji** — zakładamy, że atakujący nie ma write access do `server_data/` ani do procesu podpisującego release (w demo to założenie jest słabe; w dokumencie ryzyk je wypisz).

## Zagrożenia (minimum do opisania w dokumentacji projektu)

| Zagrożenie | Mitigacja w QRBT |
|------------|------------------|
| Podmiana manifestu / binarki | Podpisy ephemeral (AND), hash SHA-256 binarki, (opcjonalnie) Merkle inclusion |
| Fałszywy serwer | `authority_pub` provisioned out-of-band; weryfikacja `ephemeral_cert_sig_ed` |
| Downgrade wersji | Polityka wersji + stan TPM mock |
| Kompromitacja ephemeral | Rotacja czasowa; window ważności; revoke = nowa rotacja + nowe release |
| Kompromitacja authority | Poza zakresem aplikacji — procedura re-keyingu klientów |

## Granice — czego **nie** obiecujesz w prototypie

- **Poufność** aktualizacji: bez TLS treść binarki może wyciec — opisz jako residual risk.
- **Dostępność**: brak rate limit, brak CDN — OK dla hackathonu.
- **Merkle proof**: uproszczona weryfikacja (kolejność sąsiada) — jeśli nie naprawiacie, opisz ograniczenie w `04-merkle-tree-spec.md`.

## Deliverable z tego taska (dla repo „lepszego”)

Jeden plik `docs/SECURITY.md` lub sekcja w README: 1 strona A4 — tabela zagrożeń + TCB + residual risks.

## Kryteria ukończenia

- [ ] Lista zagrożeń pokrywa minimum z PDF Honeywell (integrity, authenticity, downgrade, MITM jako ryzyko transportu).
- [ ] Jasno napisane: gdzie kończy się gwarancja krypto, a zaczyna procedura operacyjna (klucze, hosting).
