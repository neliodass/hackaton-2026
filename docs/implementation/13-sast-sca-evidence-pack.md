# Task 13 — Pakiet dowodów SAST / SCA (kryteria PDF Honeywell)

## Cel

Przygotować **artefakty oceniane** przez jury: skany + krótka interpretacja — nie muszą być zerowe findings, muszą być **świadome**.

## SAST (Static Application Security Testing)

**Narzędzia (wybierz 1–2):**

- `bandit -r src/ -f json -o reports/bandit.json`
- `ruff check` (lint + niektóre klasy błędów)
- opcjonalnie Semgrep z ruleset `p/python`

**Deliverable:**

- Katalog `reports/` (gitignored) lub załącznik w release notes.
- Plik `docs/SAST.md`: tabela 5–10 alertów — dla każdego: severity, czy **true positive** / false positive, akcja (fix / accept / ignore z uzasadnieniem).

## SCA (Software Composition Analysis)

**Narzędzia:**

- `pip-audit` lub `uv pip audit`
- opcjonalnie: `cyclonedx-bom` + upload do Dependency-Track (poza MVP)

**Deliverable:**

- `docs/SCA.md`: lista zależności z znanymi CVE; jeśli brak — napisz „no known vulnerabilities at scan date” z datą.

## Integracja w repo

```toml
# fragment pyproject.toml — dev dependency group
[project.optional-dependencies]
dev = ["pytest", "httpx", "bandit", "pip-audit", "ruff"]
```

Skrypt `scripts/security_scan.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
bandit -r src -f json -o reports/bandit.json || true
pip-audit -f json -o reports/pip-audit.json || true
echo "See docs/SAST.md and docs/SCA.md for interpretation"
```

## Kryteria ukończenia

- [ ] Skrypt uruchamialny w CI jako job `security` (allow_failure opcjonalny na hackathon).
- [ ] Data skanu i wersje narzędzi zapisane w markdown.

## Pułapki

- `bandit` na `.venv` — skanuj tylko `src/`, nie site-packages.
