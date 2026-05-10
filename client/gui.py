#!/usr/bin/env python3
import hashlib
import json
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from dilithium_py.ml_dsa import ML_DSA_65
from packaging.version import Version

SERVER_URL = 'http://127.0.0.1:8000'
TPM_FILE = Path.home() / '.qrbt_tpm.json'


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_keys(server: str):
    r = requests.get(server.rstrip('/') + '/keys', timeout=15)
    r.raise_for_status()
    data = r.json()
    data['_server'] = server.rstrip('/')
    return data


def load_authority_pub() -> str:
    """Load root Ed25519 public key as PEM (used externally; verify_manifest uses /keys)."""
    candidates = [Path.home() / '.qrbt_authority_pub.pem', Path.cwd() / 'client_authority_pub.pem']
    for p in candidates:
        if p.exists():
            return p.read_text()
    raise RuntimeError(
        'Brak lokalnego pliku z publicznym kluczem authority. '
        'Umieść client_authority_pub.pem w katalogu projektu lub ~/.qrbt_authority_pub.pem'
    )


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')


def verify_manifest(manifest: dict, keys: dict, log_fn=None) -> bool:
    """Verify manifest using existing server format:
    - Root keys from /keys endpoint (in keys dict)
    - Signing cert from /cert/{id}
    - Ed25519 signature from /sig/{id} (binary)
    - ML-DSA-65 signature from /sig-pq/{id} (binary)
    """
    def _log(msg, tag=None):
        if log_fn:
            log_fn(msg, tag)

    server = keys.get('_server', SERVER_URL)
    release_id = manifest.get('id')
    if not release_id:
        _log('  [!] Manifest nie zawiera pola id', 'err')
        return False

    root_ed_hex = keys.get('root_ed25519', '')
    root_mldsa_hex = keys.get('root_mldsa65', '')
    if not root_ed_hex:
        _log('  [!] /keys nie zwróciło root_ed25519 — brak pliku keys/root/root_ed25519_pub.hex?', 'err')
        return False
    if not root_mldsa_hex:
        _log('  [!] /keys nie zwróciło root_mldsa65 — brak pliku keys/root/root_mldsa_pub.hex?', 'err')
        return False

    _log(f'  Root Ed25519 (z /keys): {root_ed_hex[:16]}…', 'dim')
    _log(f'  Root ML-DSA  (z /keys): {root_mldsa_hex[:16]}… ({len(root_mldsa_hex)//2} B)', 'dim')

    # ── Fetch signing certificate ────────────────────────────────────────────
    try:
        cert_r = requests.get(f'{server}/cert/{release_id}', timeout=15)
        cert_r.raise_for_status()
        cert = cert_r.json()
        _log(f'  Cert fetched (subject={cert.get("subject","?")}, valid_to={cert.get("valid_to","?")})', 'dim')
    except Exception as exc:
        _log(f'  [!] Błąd pobierania /cert/{release_id}: {exc}', 'err')
        return False

    # ── Verify cert with root Ed25519 key ───────────────────────────────────
    sigs = cert.get('root_signatures', {})
    cert_body = {k: v for k, v in cert.items() if k != 'root_signatures'}
    cert_data = _canonical(cert_body)

    try:
        root_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(root_ed_hex))
        root_pub.verify(bytes.fromhex(sigs['ed25519']), cert_data)
        _log('  Cert Ed25519 (root→cert): OK', 'ok')
    except Exception as exc:
        _log(f'  [!] Cert Ed25519 weryfikacja FAILED: {exc}', 'err')
        return False

    # ── Verify cert with root ML-DSA key ────────────────────────────────────
    mldsa_root_sig = sigs.get('mldsa', '')
    try:
        mldsa_key_bytes = bytes.fromhex(root_mldsa_hex)
        mldsa_sig_bytes = bytes.fromhex(mldsa_root_sig)
        _log(f'  ML-DSA root key size: {len(mldsa_key_bytes)} B, sig size: {len(mldsa_sig_bytes)} B', 'dim')

        # Try ML_DSA_65 first, fall back to ML_DSA_87 if key size matches
        from dilithium_py.ml_dsa import ML_DSA_87
        if len(mldsa_key_bytes) == 2592:
            ok = ML_DSA_87.verify(mldsa_key_bytes, cert_data, mldsa_sig_bytes, ctx=b'')
            _log('  Cert ML-DSA-87 (root→cert): ' + ('OK' if ok else 'FAILED'), 'ok' if ok else 'err')
        else:
            ok = ML_DSA_65.verify(mldsa_key_bytes, cert_data, mldsa_sig_bytes, ctx=b'')
            _log('  Cert ML-DSA-65 (root→cert): ' + ('OK' if ok else 'FAILED'), 'ok' if ok else 'err')
        if not ok:
            return False
    except Exception as exc:
        _log(f'  [!] Cert ML-DSA weryfikacja FAILED: {exc}', 'err')
        return False

    # ── Fetch binary Ed25519 manifest signature ──────────────────────────────
    try:
        sig_r = requests.get(f'{server}/sig/{release_id}', timeout=15)
        sig_r.raise_for_status()
        ed_sig = sig_r.content
        _log(f'  Ed25519 sig fetched ({len(ed_sig)} B)', 'dim')
    except Exception as exc:
        _log(f'  [!] Błąd pobierania /sig/{release_id}: {exc}', 'err')
        return False

    # ── Fetch binary ML-DSA-65 manifest signature ────────────────────────────
    try:
        pq_sig_r = requests.get(f'{server}/sig-pq/{release_id}', timeout=15)
        pq_sig_r.raise_for_status()
        pq_sig = pq_sig_r.content
        _log(f'  ML-DSA sig fetched ({len(pq_sig)} B)', 'dim')
    except Exception as exc:
        _log(f'  [!] Błąd pobierania /sig-pq/{release_id}: {exc}', 'err')
        return False

    # Canonical JSON — must match what was signed on the server
    manifest_bytes = _canonical(manifest)
    _log(f'  Canonical manifest: {len(manifest_bytes)} B, sha256={sha256_hex(manifest_bytes)[:16]}…', 'dim')

    # ── Verify Ed25519 manifest signature ────────────────────────────────────
    signing_ed_hex = cert.get('signing_pubkey', {}).get('ed25519', '')
    try:
        signing_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signing_ed_hex))
        signing_pub.verify(ed_sig, manifest_bytes)
        _log('  Manifest Ed25519: OK', 'ok')
    except Exception as exc:
        _log(f'  [!] Manifest Ed25519 FAILED: {exc}', 'err')
        return False

    # ── Verify ML-DSA manifest signature ─────────────────────────────────────
    signing_pq_hex = cert.get('signing_pubkey', {}).get('mldsa65', '')
    try:
        ok = ML_DSA_65.verify(bytes.fromhex(signing_pq_hex), manifest_bytes, pq_sig, ctx=b'')
        _log('  Manifest ML-DSA-65: ' + ('OK' if ok else 'FAILED'), 'ok' if ok else 'err')
        if not ok:
            return False
    except Exception as exc:
        _log(f'  [!] Manifest ML-DSA-65 FAILED: {exc}', 'err')
        return False

    return True


def get_tpm_version():
    if not TPM_FILE.exists():
        return '0.0.0'
    j = json.loads(TPM_FILE.read_text())
    return j.get('version', '0.0.0')


def set_tpm_version(v: str):
    TPM_FILE.write_text(json.dumps({'version': v}))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('QRBT Client — Quantum-Resistant Binary Transparency')
        self.geometry('1100x760')
        self.minsize(900, 600)

        self.bg_color = '#1a1b26'
        self.panel_bg = '#24283b'
        self.card_bg = '#1f2335'
        self.fg_color = '#c0caf5'
        self.fg_dim = '#565f89'
        self.accent_color = '#7aa2f7'
        self.accent_green = '#9ece6a'
        self.accent_mint = '#73daca'
        self.warning_color = '#f7768e'
        self.warn_soft = '#e0af68'
        self.border = '#3b4261'

        self.server = SERVER_URL
        self._last_manifest: dict | None = None
        self._last_log_snapshot: dict | None = None

        self.configure(highlightthickness=0, bd=0, relief='flat', bg=self.bg_color)
        self._main = tk.Frame(self, bg=self.bg_color, highlightthickness=0, bd=0)
        self._main.pack(fill='both', expand=True)
        self._setup_style()
        self.create_widgets()
        self._refresh_tpm_badge()

    def _setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass
        style.configure('TNotebook', background=self.bg_color, borderwidth=0,
                        relief='flat', highlightthickness=0)
        style.configure('TNotebook.Tab',
            background=self.panel_bg,
            foreground=self.fg_color,
            padding=[14, 8],
            font=('Segoe UI', 10, 'bold'),
        )
        style.map(
            'TNotebook.Tab',
            background=[('selected', self.card_bg)],
            foreground=[('selected', self.accent_mint)],
        )
        style.layout('TNotebook', [('Notebook.client', {'sticky': 'nswe'})])
        style.configure('TFrame', background=self.bg_color, relief='flat', borderwidth=0)
        style.configure('Card.TFrame', background=self.card_bg)
        style.configure('URL.TLabel', background=self.bg_color, foreground=self.fg_dim, font=('Segoe UI', 9))
        style.configure('CardTitle.TLabel', background=self.card_bg, foreground=self.accent_color, font=('Segoe UI', 9, 'bold'))
        style.configure('CardValue.TLabel', background=self.card_bg, foreground=self.fg_color, font=('Segoe UI', 11))
        style.configure('CardHint.TLabel', background=self.card_bg, foreground=self.fg_dim, font=('Segoe UI', 8))

    def create_widgets(self):
        p = self._main  # all widgets are children of the wrapper, not root

        # --- Header ---
        top = tk.Frame(p, bg=self.panel_bg, height=72, highlightthickness=0, bd=0)
        top.pack(fill='x')
        top.pack_propagate(False)

        tk.Label(
            top,
            text='QRBT Client',
            font=('Segoe UI', 18, 'bold'),
            bg=self.panel_bg,
            fg=self.fg_color,
        ).pack(side='left', padx=20, pady=16)

        tk.Label(
            top,
            text='Aktualizacje z weryfikacją podpisów (Ed25519 + ML-DSA) i transparency log',
            font=('Segoe UI', 10),
            bg=self.panel_bg,
            fg=self.fg_dim,
        ).pack(side='left', pady=16)

        # --- URL + actions ---
        bar = tk.Frame(p, bg=self.bg_color, highlightthickness=0, bd=0)
        bar.pack(fill='x', padx=16, pady=(10, 6))

        tk.Label(bar, text='URL serwera', font=('Segoe UI', 9), bg=self.bg_color, fg=self.fg_dim).pack(side='left')
        self.url_var = tk.StringVar(value=self.server)
        url_entry = tk.Entry(
            bar,
            textvariable=self.url_var,
            width=48,
            font=('Consolas', 10),
            bg=self.card_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            relief='flat',
            highlightthickness=1,
            highlightbackground=self.border,
            highlightcolor=self.accent_color,
        )
        url_entry.pack(side='left', padx=(8, 12), ipady=6)

        def apply_url():
            self.server = self.url_var.get().strip().rstrip('/') or SERVER_URL
            self.url_var.set(self.server)
            self._set_connection_badge(f'● Serwer: {self.server}', self.accent_mint)

        tk.Button(
            bar,
            text='Zapisz URL',
            command=apply_url,
            bg=self.panel_bg,
            fg=self.fg_color,
            font=('Segoe UI', 9),
            padx=12,
            pady=6,
            relief='flat',
            cursor='hand2',
            activebackground=self.border,
            activeforeground=self.fg_color,
        ).pack(side='left', padx=2)

        self.check_btn = tk.Button(
            bar,
            text='  Sprawdź aktualizacje  ',
            command=self.check_updates,
            bg=self.accent_mint,
            fg='#1a1b26',
            font=('Segoe UI', 10, 'bold'),
            padx=14,
            pady=8,
            relief='flat',
            cursor='hand2',
            activebackground='#94e2d5',
        )
        self.check_btn.pack(side='left', padx=(20, 8))

        self.install_btn = tk.Button(
            bar,
            text='  Zainstaluj latest  ',
            command=self.install_latest,
            bg='#bb9af7',
            fg='#1a1b26',
            font=('Segoe UI', 10, 'bold'),
            padx=14,
            pady=8,
            relief='flat',
            cursor='hand2',
            activebackground='#cfc9ff',
        )
        self.install_btn.pack(side='left', padx=4)

        # --- Notebook ---
        notebook = ttk.Notebook(p, style='TNotebook')
        notebook.pack(fill='both', expand=True, padx=0, pady=0)

        tab1 = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(tab1, text='  Przegląd  ')

        # Summary cards
        cards = tk.Frame(tab1, bg=self.bg_color)
        cards.pack(fill='x', padx=4, pady=(4, 8))

        self._card_manifest = self._make_card(cards, 'Ostatni manifest', '—', 'ID wydania i metadane z /latest')
        self._card_manifest.grid(row=0, column=0, sticky='nsew', padx=4, pady=4)
        self._card_crypto = self._make_card(cards, 'Łańcuch zaufania', '—', 'Root → cert ephemeral → podpisy manifestu')
        self._card_crypto.grid(row=0, column=1, sticky='nsew', padx=4, pady=4)
        self._card_tpm = self._make_card(cards, 'TPM (mock)', '—', 'Plik ~/.qrbt_tpm.json — anti-rollback')
        self._card_tpm.grid(row=0, column=2, sticky='nsew', padx=4, pady=4)
        cards.columnconfigure(0, weight=1)
        cards.columnconfigure(1, weight=1)
        cards.columnconfigure(2, weight=1)

        self.log = scrolledtext.ScrolledText(
            tab1,
            bg=self.card_bg,
            fg=self.fg_color,
            font=('JetBrains Mono', 10) if self._font_available('JetBrains Mono') else ('Consolas', 10),
            wrap='word',
            relief='flat',
            borderwidth=0,
            padx=12,
            pady=10,
            insertbackground=self.fg_color,
        )
        self.log.pack(fill='both', expand=True, padx=4, pady=4)
        for tag, cfg in [
            ('hdr', {'foreground': self.accent_color, 'font': ('Consolas', 10, 'bold')}),
            ('ok', {'foreground': self.accent_green}),
            ('warn', {'foreground': self.warn_soft}),
            ('err', {'foreground': self.warning_color}),
            ('dim', {'foreground': self.fg_dim}),
            ('mono', {'font': ('Consolas', 9)}),
        ]:
            self.log.tag_configure(tag, **cfg)

        tab2 = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(tab2, text='  Merkle / transparency  ')

        self.tree_text = scrolledtext.ScrolledText(
            tab2,
            bg=self.card_bg,
            fg=self.fg_color,
            font=('Consolas', 9),
            wrap='none',
            relief='flat',
            borderwidth=0,
            padx=12,
            pady=10,
            insertbackground=self.fg_color,
        )
        self.tree_text.pack(fill='both', expand=True, padx=4, pady=4)
        self.tree_text.tag_configure('title', foreground=self.accent_mint, font=('Consolas', 11, 'bold'))
        self.tree_text.tag_configure('hi', foreground=self.warn_soft, font=('Consolas', 9, 'bold'))
        self.tree_text.tag_configure('root', foreground=self.accent_green, font=('Consolas', 9, 'bold'))
        self.tree_text.tag_configure('dim', foreground=self.fg_dim)

        # Footer
        foot = tk.Frame(p, bg=self.panel_bg, height=36, highlightthickness=0, bd=0)
        foot.pack(side='bottom', fill='x')
        foot.pack_propagate(False)
        self.connection_label = tk.Label(
            foot,
            text='● Gotowy',
            font=('Segoe UI', 9),
            bg=self.panel_bg,
            fg=self.accent_mint,
            anchor='w',
        )
        self.connection_label.pack(fill='x', padx=16, pady=8)

    def _font_available(self, name: str) -> bool:
        try:
            f = tkfont.Font(family=name, size=10)
            return f.actual()['family'].lower() == name.lower()
        except Exception:
            return False

    def _make_card(self, parent, title: str, value: str, hint: str):
        outer = tk.Frame(parent, bg=self.border, padx=1, pady=1)
        inner = tk.Frame(outer, bg=self.card_bg, padx=14, pady=12)
        inner.pack(fill='both', expand=True)
        tk.Label(inner, text=title.upper(), font=('Segoe UI', 8, 'bold'), bg=self.card_bg, fg=self.fg_dim).pack(anchor='w')
        val_lbl = tk.Label(inner, text=value, font=('Segoe UI', 13, 'bold'), bg=self.card_bg, fg=self.accent_mint, wraplength=320, justify='left')
        val_lbl.pack(anchor='w', pady=(4, 2))
        tk.Label(inner, text=hint, font=('Segoe UI', 8), bg=self.card_bg, fg=self.fg_dim, wraplength=320, justify='left').pack(anchor='w')
        outer._value_label = val_lbl  # type: ignore[attr-defined]
        return outer

    def _card_set(self, card_frame, text: str, color: str | None = None):
        lbl = getattr(card_frame, '_value_label', None)
        if lbl is None:
            return
        lbl.config(text=text)
        if color:
            lbl.config(fg=color)

    def _set_connection_badge(self, text: str, color: str):
        self.connection_label.config(text=text, fg=color)

    def _refresh_tpm_badge(self):
        v = get_tpm_version()
        self._card_set(self._card_tpm, f'Zainstalowano: {v}', self.fg_color)

    def log_msg(self, s: str, tag: str | None = None):
        start = self.log.index('end')
        self.log.insert('end', s + '\n')
        if tag:
            self.log.tag_add(tag, start, 'end-1c')
        self.log.see('end')
        self.update()

    def check_updates(self):
        try:
            self.server = self.url_var.get().strip().rstrip('/') or SERVER_URL
            self.url_var.set(self.server)
            self._set_connection_badge('● Sprawdzam…', self.warn_soft)
            self.update()

            keys = load_keys(self.server)
            r = requests.get(self.server + '/latest', timeout=30)
            r.raise_for_status()
            manifest = r.json()
            self._last_manifest = manifest

            self.log.delete('1.0', 'end')
            self.log_msg('PODSUMOWANIE SPRAWDZENIA', 'hdr')
            self.log_msg('', None)

            mid = manifest.get('id', '?')
            ver = manifest.get('version', '?')
            self._card_set(self._card_manifest, f'v{ver}  ·  id {mid}', self.accent_mint)
            self._card_set(self._card_crypto, 'Oczekiwanie…', self.fg_dim)

            self.log_msg(f'Manifest: wersja {ver}, id {mid}', None)
            binary_name = manifest.get('binary_name') or manifest.get('package_name', '?')
            binary_size = manifest.get('binary_size') or manifest.get('size_bytes', '?')
            self.log_msg(f'Plik: {binary_name}  ·  {binary_size} B', 'dim')
            self.log_msg(f'SHA-256 (z manifestu): {manifest.get("sha256", "")}', 'mono')
            if manifest.get('notes'):
                self.log_msg(f'Notatki: {manifest["notes"]}', 'dim')
            self.log_msg('', None)

            self.log_msg('WERYFIKACJA KRYPTO', 'hdr')
            ok = verify_manifest(manifest, keys, log_fn=self.log_msg)
            if ok:
                self.log_msg('  Root (authority) → certyfikat kluczy ephemeral Ed25519  … OK', 'ok')
                self.log_msg('  Podpis ephemeral Ed25519 nad manifestem  … OK', 'ok')
                self.log_msg('  Podpis ephemeral ML-DSA-65 nad manifestem  … OK', 'ok')
                self._card_set(self._card_crypto, 'Wszystkie kroki OK', self.accent_green)
            else:
                self.log_msg('  Błąd: jeden z kroków weryfikacji nie przeszedł', 'err')
                self._card_set(self._card_crypto, 'Błąd weryfikacji', self.warning_color)
                self._set_connection_badge('● Błąd weryfikacji', self.warning_color)
                return

            log_r = requests.get(self.server + '/log', timeout=15)
            log_r.raise_for_status()
            log_data = log_r.json()
            self._last_log_snapshot = log_data
            entries = log_data.get('entries') or []
            root_hex = log_data.get('root') or '—'
            self.log_msg('', None)
            self.log_msg('TRANSPARENCY LOG (/log)', 'hdr')
            self.log_msg(f'  Wpisy w logu: {len(entries)}  ·  Merkle root: {root_hex[:24]}…', 'dim')

            proof_r = requests.get(self.server + f"/proof/{mid}", timeout=15)
            proof_r.raise_for_status()
            proof = proof_r.json()
            self.log_msg(f'  Dowód inclusion: {len(proof.get("proof", []))} poziom(ów) sąsiadów', 'dim')
            self.log_msg(f'  Root z /proof: {proof.get("root", "")[:32]}…', 'dim')

            leaf_idx = next((i for i, e in enumerate(entries) if e.get('id') == mid), None)

            tree_r = requests.get(self.server + '/merkle-tree', timeout=15)
            tree_r.raise_for_status()
            tree_data = tree_r.json()
            self.draw_merkle_tree(tree_data, highlight_index=leaf_idx, manifest_id=mid, log_count=len(entries))

            tpm_v = get_tpm_version()
            self._refresh_tpm_badge()
            self.log_msg('', None)
            self.log_msg('ANTI-ROLLBACK (TPM mock)', 'hdr')
            self.log_msg(f'  Wersja w TPM: {tpm_v}  ·  wersja w manifeście: {ver}', None)
            if Version(ver) <= Version(tpm_v):
                self.log_msg('  Wynik: brak nowszej wersji (nie zainstalujesz downgrade)', 'warn')
                self._card_set(self._card_tpm, f'TPM: {tpm_v} — blokada', self.warn_soft)
            else:
                self.log_msg('  Wynik: można bezpiecznie zainstalować (wersja nowsza niż TPM)', 'ok')
                self._card_set(self._card_tpm, f'TPM: {tpm_v} → można {ver}', self.accent_green)

            self._set_connection_badge(f'● Gotowy  ·  {self.server}', self.accent_mint)

        except Exception as e:
            self.log_msg(f'Błąd: {e}', 'err')
            self._set_connection_badge('● Błąd połączenia', self.warning_color)
            self._card_set(self._card_manifest, '—', self.fg_dim)
            self._card_set(self._card_crypto, '—', self.fg_dim)
            messagebox.showerror('Błąd', str(e))

    def draw_merkle_tree(self, tree_data: dict, highlight_index: int | None, manifest_id: str, log_count: int):
        self.tree_text.delete('1.0', 'end')
        self.tree_text.insert('end', 'TRANSPARENCY LOG — struktura Merkle\n\n', 'title')

        leaves = tree_data.get('leaves', [])
        layers = tree_data.get('layers', [])
        root = tree_data.get('root', '')

        self.tree_text.insert('end', f'Powiązany manifest: id {manifest_id}\n', None)
        self.tree_text.insert('end', f'Liczba liści (wydania w logu): {len(leaves)}  ·  wpisy /log: {log_count}\n\n', 'dim')

        self.tree_text.insert('end', 'LIŚCIE (hash kanonicznego manifestu + id)\n', None)
        for i, leaf in enumerate(leaves):
            use_hi = highlight_index is not None and i == highlight_index
            prefix = '  ▸ ' if use_hi else '    '
            line = f'{prefix}[{i}] {leaf}\n'
            if use_hi:
                self.tree_text.insert('end', line, 'hi')
            else:
                self.tree_text.insert('end', line)
        self.tree_text.insert('end', '\n')

        if layers:
            self.tree_text.insert('end', 'POZIOMY (liście → korzeń)\n', None)
            for layer in layers:
                level = layer['level']
                hashes = layer['hashes']
                self.tree_text.insert('end', f'  Poziom {level} — {len(hashes)} węzł(ów)\n', 'dim')
                for h in hashes:
                    self.tree_text.insert('end', f'      {h}\n', None)
                self.tree_text.insert('end', '\n')

        self.tree_text.insert('end', 'KORZEŃ (commitment)\n', 'root')
        self.tree_text.insert('end', f'{root}\n\n', 'root')
        self.tree_text.insert(
            'end',
            'Uwaga: klient weryfikuje podpisy i SHA binarki; dowód Merkle jest pokazany informacyjnie.\n',
            'dim',
        )

    def install_latest(self):
        try:
            self.server = self.url_var.get().strip().rstrip('/') or SERVER_URL
            self.url_var.set(self.server)
            self._set_connection_badge('● Instalacja…', self.warn_soft)
            self.update()

            r = requests.get(self.server + '/latest', timeout=30)
            r.raise_for_status()
            manifest = r.json()
            keys = load_keys(self.server)

            self.log_msg('', None)
            self.log_msg('INSTALACJA', 'hdr')

            if not verify_manifest(manifest, keys, log_fn=self.log_msg):
                self.log_msg('Przerwano: weryfikacja manifestu nie powiodła się', 'err')
                self._set_connection_badge('● Błąd', self.warning_color)
                return

            self.log_msg('Manifest i podpisy OK', 'ok')

            tpm_v = get_tpm_version()
            ver = manifest['version']
            if Version(ver) <= Version(tpm_v):
                self.log_msg(f'Anti-rollback: {ver} nie jest nowsze niż TPM ({tpm_v})', 'warn')
                self._set_connection_badge('● Zablokowano (TPM)', self.warn_soft)
                return

            bin_r = requests.get(self.server + f"/binary/{manifest['id']}", timeout=120)
            bin_r.raise_for_status()
            data = bin_r.content

            self.log_msg(f'Pobrano {len(data)} B', None)
            if sha256_hex(data) != manifest['sha256']:
                self.log_msg('SHA-256 binarki ≠ manifest — przerwano', 'err')
                self._set_connection_badge('● Błąd', self.warning_color)
                return

            self.log_msg('SHA-256 zgodny z manifestem', 'ok')

            # Use the original filename from the manifest
            pkg_name = manifest.get('package_name') or f"update_{manifest['id']}.bin"
            stem = Path(pkg_name).stem
            suffix = Path(pkg_name).suffix or '.bin'
            out = Path.home() / f"qrbt_installed_{stem}_{manifest['id']}{suffix}"
            out.write_bytes(data)
            set_tpm_version(ver)
            self._refresh_tpm_badge()
            self._card_set(self._card_manifest, f'v{ver}  ·  id {manifest["id"]}', self.accent_mint)

            self.log_msg(f'Zapisano: {out}', 'ok')
            self.log_msg(f'TPM zaktualizowany do: {ver}', 'ok')

            # Preview file content
            self.log_msg('', None)
            self.log_msg(f'ZAWARTOŚĆ PLIKU [{pkg_name}]', 'hdr')
            try:
                text = data.decode('utf-8')
                for line in text.splitlines():
                    self.log_msg(f'  {line}', 'mono')
            except UnicodeDecodeError:
                self.log_msg(f'  [plik binarny — hex dump pierwszych {min(len(data), 256)} B]', 'dim')
                chunk = data[:256]
                for offset in range(0, len(chunk), 16):
                    row = chunk[offset:offset + 16]
                    hex_part = ' '.join(f'{b:02x}' for b in row)
                    asc_part = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in row)
                    self.log_msg(f'  {offset:04x}  {hex_part:<47}  |{asc_part}|', 'mono')
                if len(data) > 256:
                    self.log_msg(f'  ... ({len(data) - 256} bajtów pominięto)', 'dim')

            self._set_connection_badge(f'● Zainstalowano {ver}', self.accent_green)
            messagebox.showinfo('Sukces', f'Zainstalowano wersję {ver}\n\nPlik:\n{out}')

        except Exception as e:
            self.log_msg(f'Błąd: {e}', 'err')
            self._set_connection_badge('● Błąd', self.warning_color)
            messagebox.showerror('Błąd', str(e))


if __name__ == '__main__':
    app = App()
    app.mainloop()
