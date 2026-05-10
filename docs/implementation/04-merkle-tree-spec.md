# Task 04 — Specyfikacja Merkle Tree i API dowodów

## Cel

Zaimplementować drzewo Merkle nad listą `hash` manifestów, endpointy `/log`, `/proof/{id}`, `/merkle-tree` — zgodnie z zachowaniem prototypu lub z **poprawką** weryfikacji proof.

## Budowa drzewa (jak w prototypie)

- **Liść**: `H(raw_leaf)` gdzie `raw_leaf = bytes.fromhex(entry_hash)` — *uwaga*: w prototypie liść to hash **hex zdekodowany do bytes**; utrwal to w specyfikacji, żeby klient liczył identycznie.
- **Węzeł wewnętrzny**: `H(left || right)`; jeśli nieparzysta liczba węzłów, ostatni **duplikowany** (para z samym sobą).
- **Root**: pojedynczy digest na ostatnim poziomie.

## Inclusion proof (prototyp)

- `get_proof(idx)` zwraca listę sąsiadów po drodze do roota.
- `verify_proof` w prototypie jest uproszczony (kolejność łączenia).

### Zalecenie dla „lepszego” repo

Rozszerz proof o **bit `is_right`** przy każdym poziomie albo precomputed `sibling_is_left`, żeby weryfikacja była jednoznaczna:

```text
cur = H(leaf)
for (sibling, position) in proof:
    cur = H(cur || sibling) if position == 'L' else H(sibling || cur)
assert cur == root
```

Jeśli zostajesz przy zachowaniu prototypu — **udokumentuj**, że proof jest best-effort pod wizualizację, a twarda gwarancja to zgodność `hash` z logiem + podpisy.

## Endpointy (kontrakt JSON)

### `GET /log`

```json
{
  "root": "<hex lub null>",
  "entries": [{ "id": "...", "hash": "..." }]
}
```

### `GET /proof/{id}`

```json
{
  "proof": ["<hex>", "..."],
  "root": "<hex>"
}
```

404 jeśli `id` nie ma w `entries`.

### `GET /merkle-tree`

Zwraca `leaves`, `root`, `layers[]` z `level` + `hashes` — wyłącznie pod UI; nie jest to część twardego TCB klienta CLI.

## Kryteria ukończenia

- [ ] Dla pustego logu: `root: null`, brak wyjątków.
- [ ] Dla N=1 manifestu: proof pusty lub zgodny ze specyfikacją; root == H(H(leaf)) łańcuch zgodny z implementacją.
- [ ] Test: dodaj 3 release → root się zmienia; proof dla środkowego indeksu odtwarza root (jeśli poprawisz verify) albo przynajmniej `get_proof` nie rzuca.

## Pułapki

- Dekodowanie hex: małe/duże litery — użyj `bytes.fromhex` i **spójnego** lower na serwerze przy zapisie.
- `json.dumps(manifest, sort_keys=True)` do hash manifestu **nie** jest tym samym co leaf w drzewie — leaf to hash z logu (już SHA256 całego manifestu).
