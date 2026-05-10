#!/usr/bin/env python3
"""QRBT Server GUI — zarządzanie serwerem aktualizacji."""
import json
import logging
import os
import subprocess  # nosec B404
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

import requests
from packaging.version import Version

# ── Import modules from server/src ───────────────────────────────────────────
_SRC = Path(__file__).resolve().parent / "src"
sys.path.insert(0, str(_SRC))

from config import (  # noqa: E402
    HOST,
    LATEST_POINTER_PATH,
    MERKLE_SERVICE_URL,
    PORT,
    VERSIONS_DIR,
)
from manifest import request_signature_from_signing_machine  # noqa: E402
from release import create_new_release  # noqa: E402


# ── Logging bridge ────────────────────────────────────────────────────────────
class _WidgetHandler(logging.Handler):
    """Forwards log records to a Tk text widget."""

    def __init__(self, widget: scrolledtext.ScrolledText):
        super().__init__()
        self._widget = widget

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        level = record.levelno
        tag = "info"
        if level >= logging.ERROR:
            tag = "err"
        elif level >= logging.WARNING:
            tag = "warn"
        try:
            self._widget.after(0, self._append, msg, tag)
        except tk.TclError:  # widget may be destroyed
            pass

    def _append(self, msg: str, tag: str) -> None:
        self._widget.configure(state="normal")
        start = self._widget.index("end")
        self._widget.insert("end", msg + "\n")
        self._widget.tag_add(tag, start, "end-1c")
        self._widget.configure(state="disabled")
        self._widget.see("end")


# ── Uvicorn subprocess manager ────────────────────────────────────────────────
# Running uvicorn inside a thread on Windows causes asyncio event-loop conflicts
# with Tkinter. Using a subprocess is simpler and more reliable.
class _ServerProcess:
    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._log_cb = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, host: str, port: int, log_cb=None) -> None:
        if self.running:
            return
        self._log_cb = log_cb
        env = os.environ.copy()
        env["UPDATE_SERVER_HOST"] = host
        env["UPDATE_SERVER_PORT"] = str(port)
        self._proc = subprocess.Popen(  # nosec B603
            [sys.executable, "-m", "uvicorn", "app:app",
             "--host", host, "--port", str(port), "--log-level", "info"],
            cwd=str(_SRC),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        threading.Thread(target=self._drain, daemon=True, name="srv-log").start()

    def _drain(self) -> None:
        if self._proc and self._proc.stdout:
            for line in self._proc.stdout:
                line = line.rstrip()
                if line and self._log_cb:
                    self._log_cb(line)

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            self._proc = None


_srv = _ServerProcess()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _load_versions() -> list[tuple[Path, dict]]:
    if not VERSIONS_DIR.exists():
        return []
    entries = []
    for d in sorted(VERSIONS_DIR.iterdir()):
        mp = d / "manifest.json"
        if not d.is_dir() or not mp.exists():
            continue
        try:
            entries.append((d, json.loads(mp.read_text(encoding="utf-8"))))
        except (json.JSONDecodeError, OSError):
            continue
    return entries


def _latest_id() -> str | None:
    if not LATEST_POINTER_PATH.exists():
        return None
    try:
        return json.loads(LATEST_POINTER_PATH.read_text(encoding="utf-8")).get("id")
    except (json.JSONDecodeError, OSError):
        return None


def _bump_version(current: str, bump: str) -> str:
    """Return next version string for bump type: bugfix / feature / major."""
    try:
        v = Version(current)
        major, minor, patch = v.major, v.minor, v.micro
    except Exception:
        major, minor, patch = 0, 0, 0
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "feature":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _latest_version() -> str:
    """Return the version string of the latest release, or '0.0.0' if none."""
    lid = _latest_id()
    if lid is None:
        return "0.0.0"
    mp = VERSIONS_DIR / lid / "manifest.json"
    try:
        return json.loads(mp.read_text(encoding="utf-8")).get("version", "0.0.0")
    except (json.JSONDecodeError, OSError):
        return "0.0.0"


# ── Add-version dialog ────────────────────────────────────────────────────────
class _AddVersionDialog(tk.Toplevel):
    """Modal dialog: choose version + source (file picker OR text editor)."""

    BG    = "#1a1b26"
    PANEL = "#24283b"
    CARD  = "#1f2335"
    FG    = "#c0caf5"
    FG_DIM= "#565f89"
    ACCENT= "#7aa2f7"
    GREEN = "#9ece6a"
    MINT  = "#73daca"
    RED   = "#f7768e"
    ORANGE= "#e0af68"
    BORDER= "#3b4261"

    def __init__(self, parent: tk.Tk) -> None:
        super().__init__(parent)
        self.title("Dodaj nową wersję")
        self.configure(bg=self.BG)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # result fields
        self.version: str | None = None
        self.source_file: Path | None = None
        self.text_content: str | None = None

        self._current_ver = _latest_version()
        self._bump = tk.StringVar(value="bugfix")
        self._mode = tk.StringVar(value="text")
        self._picked_path: Path | None = None

        self._build()
        self.update_idletasks()
        # centre over parent
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        w, h = self.winfo_width(), self.winfo_height()
        self.geometry(f"+{px + (pw - w)//2}+{py + (ph - h)//2}")
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    # ----- widget helpers -----
    def _lbl(self, parent, text, **kw):
        kw.setdefault("fg", self.FG)
        return tk.Label(parent, text=text, bg=self.BG,
                        font=("Segoe UI", 9), **kw)

    def _btn(self, parent, text, cmd, bg=None, fg=None):
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg or self.PANEL, fg=fg or self.FG,
                         font=("Segoe UI", 9, "bold"),
                         padx=10, pady=5, relief="flat", cursor="hand2",
                         activebackground=self.BORDER, activeforeground=self.FG)

    def _entry(self, parent, var, width=30):
        return tk.Entry(parent, textvariable=var, width=width,
                        font=("Consolas", 10), bg=self.CARD, fg=self.FG,
                        insertbackground=self.FG, relief="flat",
                        highlightthickness=1,
                        highlightbackground=self.BORDER,
                        highlightcolor=self.ACCENT)

    # ----- build -----
    def _build(self) -> None:
        pad = {"padx": 16, "pady": 6}

        # Current version info
        cur_row = tk.Frame(self, bg=self.BG)
        cur_row.pack(fill="x", padx=16, pady=(14, 2))
        self._lbl(cur_row, "Aktualna wersja:", fg=self.FG_DIM).pack(side="left")
        tk.Label(cur_row, text=self._current_ver, bg=self.BG, fg=self.ORANGE,
                 font=("Consolas", 11, "bold")).pack(side="left", padx=(8, 0))

        # Bump type radios
        self._lbl(self, "Typ zmiany:", fg=self.FG_DIM).pack(anchor="w", padx=16, pady=(8, 2))

        bump_frame = tk.Frame(self, bg=self.PANEL, padx=12, pady=10)
        bump_frame.pack(fill="x", padx=16, pady=(0, 6))

        radio_opts = {"bg": self.PANEL, "activebackground": self.PANEL,
                      "selectcolor": self.CARD, "cursor": "hand2", "relief": "flat"}

        bumps = [
            ("bugfix",  "Bugfix",  f"patch +1   →  {_bump_version(self._current_ver, 'bugfix')}",  self.GREEN),
            ("feature", "Feature", f"minor +1   →  {_bump_version(self._current_ver, 'feature')}", self.ACCENT),
            ("major",   "Major",   f"major +1   →  {_bump_version(self._current_ver, 'major')}",   self.RED),
        ]

        for value, label, hint, color in bumps:
            row = tk.Frame(bump_frame, bg=self.PANEL)
            row.pack(fill="x", pady=2)
            tk.Radiobutton(row, text=label, variable=self._bump, value=value,
                           command=self._on_bump_change,
                           fg=color, font=("Segoe UI", 10, "bold"),
                           **radio_opts).pack(side="left")
            tk.Label(row, text=hint, bg=self.PANEL, fg=self.FG_DIM,
                     font=("Consolas", 9)).pack(side="left", padx=(10, 0))

        # New version preview
        preview_row = tk.Frame(self, bg=self.BG)
        preview_row.pack(fill="x", padx=16, pady=(2, 6))
        self._lbl(preview_row, "Nowa wersja:", fg=self.FG_DIM).pack(side="left")
        self._preview_lbl = tk.Label(
            preview_row,
            text=_bump_version(self._current_ver, "bugfix"),
            bg=self.BG, fg=self.MINT,
            font=("Consolas", 14, "bold"),
        )
        self._preview_lbl.pack(side="left", padx=(8, 0))

        sep1 = tk.Frame(self, bg=self.BORDER, height=1)
        sep1.pack(fill="x", padx=16, pady=4)

        # Source choice
        self._lbl(self, "Źródło pakietu:", fg=self.FG_DIM).pack(anchor="w", padx=16)
        radio_frame = tk.Frame(self, bg=self.BG)
        radio_frame.pack(fill="x", padx=16, pady=(2, 6))

        radio_opts = {"bg": self.BG, "fg": self.FG, "activebackground": self.BG,
                      "activeforeground": self.MINT, "selectcolor": self.PANEL,
                      "font": ("Segoe UI", 9), "cursor": "hand2", "relief": "flat"}
        tk.Radiobutton(radio_frame, text="1. Załącz plik z dysku",
                       variable=self._mode, value="file",
                       command=self._on_mode_change, **radio_opts).pack(anchor="w")
        tk.Radiobutton(radio_frame, text="2. Edytor tekstu (zapisany jako .txt)",
                       variable=self._mode, value="text",
                       command=self._on_mode_change, **radio_opts).pack(anchor="w", pady=(4, 0))

        sep2 = tk.Frame(self, bg=self.BORDER, height=1)
        sep2.pack(fill="x", padx=16, pady=4)

        # Dynamic content area
        self._content_frame = tk.Frame(self, bg=self.BG)
        self._content_frame.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        self._build_file_area()
        self._build_text_area()
        self._on_mode_change()  # show correct area

        sep3 = tk.Frame(self, bg=self.BORDER, height=1)
        sep3.pack(fill="x", padx=16, pady=4)

        # Buttons row
        btn_row = tk.Frame(self, bg=self.BG)
        btn_row.pack(fill="x", padx=16, pady=(4, 14))
        self._btn(btn_row, "Anuluj", self._cancel,
                  bg=self.PANEL, fg=self.FG_DIM).pack(side="right", padx=(4, 0))
        self._btn(btn_row, "✓  Utwórz wersję", self._ok,
                  bg="#bb9af7", fg="#1a1b26").pack(side="right")

    def _build_file_area(self) -> None:
        self._file_frame = tk.Frame(self._content_frame, bg=self.BG)
        self._file_lbl = tk.Label(
            self._file_frame, text="(nie wybrano pliku)",
            bg=self.CARD, fg=self.FG_DIM,
            font=("Consolas", 9), anchor="w", padx=8, pady=6,
            relief="flat", highlightthickness=1, highlightbackground=self.BORDER,
        )
        self._file_lbl.pack(fill="x", expand=True, side="left", padx=(0, 8))
        self._btn(self._file_frame, "Wybierz plik…", self._pick_file,
                  bg=self.PANEL, fg=self.ACCENT).pack(side="left")

    def _build_text_area(self) -> None:
        self._text_frame = tk.Frame(self._content_frame, bg=self.BG)
        self._text_lbl = tk.Label(self._text_frame, text="Treść pliku update.txt:",
                                  bg=self.BG, fg=self.FG_DIM, font=("Segoe UI", 8))
        self._text_lbl.pack(anchor="w", pady=(0, 2))
        self._text_widget = tk.Text(
            self._text_frame,
            width=56, height=10,
            bg=self.CARD, fg=self.FG, insertbackground=self.FG,
            font=("Consolas", 9), relief="flat",
            highlightthickness=1, highlightbackground=self.BORDER,
            highlightcolor=self.ACCENT,
            wrap="word", padx=8, pady=6,
        )
        self._text_widget.pack(fill="both", expand=True)

    def _on_bump_change(self) -> None:
        new_ver = _bump_version(self._current_ver, self._bump.get())
        self._preview_lbl.config(text=new_ver)

    def _on_mode_change(self) -> None:
        for w in self._content_frame.winfo_children():
            w.pack_forget()
        if self._mode.get() == "file":
            self._file_frame.pack(fill="x", pady=4)
        else:
            self._text_frame.pack(fill="both", expand=True, pady=4)

    def _pick_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Wybierz plik pakietu",
            filetypes=[
                ("Wszystkie pliki", "*.*"),
                ("Pliki tekstowe", "*.txt"),
                ("Zip", "*.zip"),
                ("Binarne", "*.bin"),
            ],
        )
        if path:
            self._picked_path = Path(path)
            self._file_lbl.config(
                text=str(self._picked_path), fg=self.MINT
            )

    # ----- result -----
    def _ok(self) -> None:
        ver = _bump_version(self._current_ver, self._bump.get())

        mode = self._mode.get()
        if mode == "file":
            if self._picked_path is None:
                tk.messagebox.showerror("Błąd", "Nie wybrano pliku.", parent=self)
                return
            self.source_file = self._picked_path
        else:
            content = self._text_widget.get("1.0", "end-1c").strip()
            if not content:
                tk.messagebox.showerror("Błąd", "Treść pliku nie może być pusta.", parent=self)
                return
            self.text_content = content

        self.version = ver
        self.grab_release()
        self.destroy()

    def _cancel(self) -> None:
        self.grab_release()
        self.destroy()


# ── App ───────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    # ── palette (same as client GUI) ─────────────────────────────────────────
    BG       = "#1a1b26"
    PANEL    = "#24283b"
    CARD     = "#1f2335"
    FG       = "#c0caf5"
    FG_DIM   = "#565f89"
    ACCENT   = "#7aa2f7"
    GREEN    = "#9ece6a"
    MINT     = "#73daca"
    RED      = "#f7768e"
    ORANGE   = "#e0af68"
    BORDER   = "#3b4261"

    def __init__(self) -> None:
        super().__init__()
        self.title("QRBT Server — Update Server Manager")
        self.geometry("1200x780")
        self.minsize(960, 620)
        self.configure(bg=self.BG)

        self._host_var = tk.StringVar(value=HOST)
        self._port_var = tk.StringVar(value=str(PORT))

        self._setup_style()
        self._build_ui()
        self._refresh_versions()

        # attach logging handler
        handler = _WidgetHandler(self._log)
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s",
                                               datefmt="%H:%M:%S"))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

        self._poll_status()

    # ── style ─────────────────────────────────────────────────────────────────
    def _setup_style(self) -> None:
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TNotebook", background=self.BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=self.PANEL, foreground=self.FG,
                    padding=[14, 8], font=("Segoe UI", 10, "bold"))
        s.map("TNotebook.Tab",
              background=[("selected", self.CARD)],
              foreground=[("selected", self.MINT)])
        s.configure("TFrame", background=self.BG)

    # ── UI construction ───────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        self._build_header()
        self._build_controls()
        self._build_notebook()
        self._build_footer()

    def _build_header(self) -> None:
        top = tk.Frame(self, bg=self.PANEL, height=72)
        top.pack(fill="x")
        top.pack_propagate(False)
        tk.Label(top, text="QRBT Server", font=("Segoe UI", 18, "bold"),
                 bg=self.PANEL, fg=self.FG).pack(side="left", padx=20, pady=16)
        tk.Label(top, text="Serwer aktualizacji z podpisami Ed25519 + ML-DSA i Merkle transparency log",
                 font=("Segoe UI", 10), bg=self.PANEL, fg=self.FG_DIM).pack(side="left", pady=16)

    def _build_controls(self) -> None:
        bar = tk.Frame(self, bg=self.BG)
        bar.pack(fill="x", padx=16, pady=(12, 6))

        # Host / Port fields
        tk.Label(bar, text="Host", font=("Segoe UI", 9), bg=self.BG, fg=self.FG_DIM).pack(side="left")
        self._entry(bar, self._host_var, width=14).pack(side="left", padx=(4, 10), ipady=5)
        tk.Label(bar, text="Port", font=("Segoe UI", 9), bg=self.BG, fg=self.FG_DIM).pack(side="left")
        self._entry(bar, self._port_var, width=7).pack(side="left", padx=(4, 20), ipady=5)

        # Action buttons
        self._btn_start = self._button(bar, "▶  Start serwera", self._start_server,
                                       bg=self.MINT, fg="#1a1b26")
        self._btn_start.pack(side="left", padx=4)

        self._btn_stop = self._button(bar, "■  Stop", self._stop_server,
                                      bg=self.PANEL, fg=self.RED)
        self._btn_stop.pack(side="left", padx=4)
        self._btn_stop.configure(state="disabled")

        tk.Frame(bar, bg=self.BG, width=20).pack(side="left")

        self._button(bar, "+  Dodaj wersję", self._add_version,
                     bg="#bb9af7", fg="#1a1b26").pack(side="left", padx=4)

        self._button(bar, "⟳  Odśwież", self._refresh_versions,
                     bg=self.PANEL, fg=self.FG).pack(side="left", padx=4)

    def _build_notebook(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=(4, 0))

        self._tab_versions(nb)
        self._tab_merkle(nb)
        self._tab_log(nb)

    def _tab_versions(self, nb: ttk.Notebook) -> None:
        frame = tk.Frame(nb, bg=self.BG)
        nb.add(frame, text="  Wersje  ")

        # Summary cards row
        cards = tk.Frame(frame, bg=self.BG)
        cards.pack(fill="x", padx=4, pady=(6, 6))
        self._card_latest  = self._make_card(cards, "Najnowsza wersja",  "—", "latest.json → /latest")
        self._card_count   = self._make_card(cards, "Wersje w rejestrze", "—", "packages/versions/")
        self._card_merkle_status = self._make_card(cards, "Merkle service", "—", f"http://127.0.0.1:{MERKLE_SERVICE_URL.split(':')[-1]}/log")
        for i, c in enumerate([self._card_latest, self._card_count, self._card_merkle_status]):
            c.grid(row=0, column=i, sticky="nsew", padx=4, pady=2)
        cards.columnconfigure(0, weight=1)
        cards.columnconfigure(1, weight=1)
        cards.columnconfigure(2, weight=1)

        # Versions table
        self._versions_text = scrolledtext.ScrolledText(
            frame, bg=self.CARD, fg=self.FG,
            font=self._mono_font(10), wrap="none",
            relief="flat", borderwidth=0, padx=12, pady=10,
            state="disabled",
        )
        self._versions_text.pack(fill="both", expand=True, padx=4, pady=4)
        for tag, cfg in [
            ("hdr",    {"foreground": self.ACCENT,  "font": self._mono_font(10, bold=True)}),
            ("latest", {"foreground": self.MINT,    "font": self._mono_font(10, bold=True)}),
            ("dim",    {"foreground": self.FG_DIM}),
            ("ok",     {"foreground": self.GREEN}),
            ("ver",    {"foreground": self.ORANGE}),
        ]:
            self._versions_text.tag_configure(tag, **cfg)

    def _tab_merkle(self, nb: ttk.Notebook) -> None:
        frame = tk.Frame(nb, bg=self.BG)
        nb.add(frame, text="  Merkle / transparency  ")

        btn_bar = tk.Frame(frame, bg=self.BG)
        btn_bar.pack(fill="x", padx=4, pady=(6, 4))
        self._button(btn_bar, "⟳  Pobierz drzewo", self._refresh_merkle,
                     bg=self.PANEL, fg=self.MINT).pack(side="left", padx=4)

        self._merkle_text = scrolledtext.ScrolledText(
            frame, bg=self.CARD, fg=self.FG,
            font=self._mono_font(9), wrap="none",
            relief="flat", borderwidth=0, padx=12, pady=10,
            state="disabled",
        )
        self._merkle_text.pack(fill="both", expand=True, padx=4, pady=4)
        for tag, cfg in [
            ("title", {"foreground": self.MINT,   "font": self._mono_font(11, bold=True)}),
            ("root",  {"foreground": self.GREEN,  "font": self._mono_font(9,  bold=True)}),
            ("hi",    {"foreground": self.ORANGE, "font": self._mono_font(9,  bold=True)}),
            ("dim",   {"foreground": self.FG_DIM}),
            ("err",   {"foreground": self.RED}),
        ]:
            self._merkle_text.tag_configure(tag, **cfg)

    def _tab_log(self, nb: ttk.Notebook) -> None:
        frame = tk.Frame(nb, bg=self.BG)
        nb.add(frame, text="  Log serwera  ")

        btn_bar = tk.Frame(frame, bg=self.BG)
        btn_bar.pack(fill="x", padx=4, pady=(6, 4))
        self._button(btn_bar, "Wyczyść", self._clear_log,
                     bg=self.PANEL, fg=self.FG_DIM).pack(side="left", padx=4)

        self._log = scrolledtext.ScrolledText(
            frame, bg=self.CARD, fg=self.FG,
            font=self._mono_font(9), wrap="word",
            relief="flat", borderwidth=0, padx=12, pady=10,
            state="disabled",
        )
        self._log.pack(fill="both", expand=True, padx=4, pady=4)
        for tag, cfg in [
            ("info", {"foreground": self.FG}),
            ("warn", {"foreground": self.ORANGE}),
            ("err",  {"foreground": self.RED}),
        ]:
            self._log.tag_configure(tag, **cfg)

    def _build_footer(self) -> None:
        foot = tk.Frame(self, bg=self.PANEL, height=36)
        foot.pack(side="bottom", fill="x")
        foot.pack_propagate(False)
        self._status_lbl = tk.Label(
            foot, text="● Zatrzymany", font=("Segoe UI", 9),
            bg=self.PANEL, fg=self.FG_DIM, anchor="w",
        )
        self._status_lbl.pack(fill="x", padx=16, pady=8)

    # ── Widget factories ──────────────────────────────────────────────────────
    def _entry(self, parent, var, width=20):
        return tk.Entry(parent, textvariable=var, width=width,
                        font=("Consolas", 10), bg=self.CARD, fg=self.FG,
                        insertbackground=self.FG, relief="flat",
                        highlightthickness=1, highlightbackground=self.BORDER,
                        highlightcolor=self.ACCENT)

    def _button(self, parent, text, cmd, bg=None, fg=None):
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg or self.PANEL, fg=fg or self.FG,
                         font=("Segoe UI", 9, "bold"),
                         padx=12, pady=6, relief="flat", cursor="hand2",
                         activebackground=self.BORDER, activeforeground=self.FG)

    def _make_card(self, parent, title, value, hint):
        outer = tk.Frame(parent, bg=self.BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=self.CARD, padx=14, pady=10)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text=title.upper(), font=("Segoe UI", 8, "bold"),
                 bg=self.CARD, fg=self.FG_DIM).pack(anchor="w")
        val = tk.Label(inner, text=value, font=("Segoe UI", 12, "bold"),
                       bg=self.CARD, fg=self.MINT, wraplength=300, justify="left")
        val.pack(anchor="w", pady=(4, 2))
        tk.Label(inner, text=hint, font=("Segoe UI", 8),
                 bg=self.CARD, fg=self.FG_DIM, wraplength=300, justify="left").pack(anchor="w")
        outer._val = val  # type: ignore[attr-defined]
        return outer

    def _card_set(self, card, text, color=None):
        lbl = getattr(card, "_val", None)
        if lbl:
            lbl.config(text=text, fg=color or self.MINT)

    def _mono_font(self, size=10, bold=False):
        families = ["JetBrains Mono", "Consolas", "Courier New"]
        for fam in families:
            try:
                f = tkfont.Font(family=fam, size=size)
                if f.actual()["family"].lower() == fam.lower():
                    return (fam, size, "bold") if bold else (fam, size)
            except tk.TclError:
                pass
        return ("Consolas", size, "bold") if bold else ("Consolas", size)

    # ── Server control ────────────────────────────────────────────────────────
    def _start_server(self) -> None:
        if _srv.running:
            self._set_status("● Już działa", self.GREEN)
            return
        host = self._host_var.get().strip() or HOST
        try:
            port = int(self._port_var.get().strip())
        except ValueError:
            messagebox.showerror("Błąd", "Nieprawidłowy numer portu.")
            return

        logging.info("Requesting signatures from signing machine…")
        threading.Thread(target=request_signature_from_signing_machine, daemon=True).start()

        def _srv_log(line: str) -> None:
            self.after(0, self._append_log, line)

        _srv.start(host, port, log_cb=_srv_log)
        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(state="normal")
        self._set_status(f"● Działa  ·  http://{host}:{port}", self.GREEN)
        logging.info("Server process started on http://%s:%d", host, port)

    def _stop_server(self) -> None:
        _srv.stop()
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._set_status("● Zatrzymany", self.FG_DIM)
        logging.info("Server stopped.")

    # ── Add version ───────────────────────────────────────────────────────────
    def _add_version(self) -> None:
        dlg = _AddVersionDialog(self)
        self.wait_window(dlg)

        if dlg.version is None:
            return  # cancelled

        version = dlg.version
        source_file = dlg.source_file
        text_content = dlg.text_content

        self._set_status(f"● Tworzę wersję {version}…", self.ORANGE)
        self.update()

        def _worker():
            try:
                create_new_release(version, source_file=source_file, text_content=text_content)
                self.after(0, self._on_version_created, version)
            except Exception as exc:
                logging.error("create_new_release failed: %s", exc)
                self.after(0, self._on_version_error, str(exc))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_version_created(self, version: str) -> None:
        self._refresh_versions()
        self._refresh_merkle()
        self._set_status(f"● Wersja {version} dodana", self.GREEN)
        messagebox.showinfo("Sukces", f"Wersja {version} została utworzona i zarejestrowana w Merkle log.")

    def _on_version_error(self, msg: str) -> None:
        self._set_status("● Błąd tworzenia wersji", self.RED)
        messagebox.showerror("Błąd", f"Nie udało się utworzyć wersji:\n{msg}")

    # ── Versions tab ──────────────────────────────────────────────────────────
    def _refresh_versions(self) -> None:
        versions = _load_versions()
        latest = _latest_id()

        # Update cards — use latest.json pointer, not alphabetical sort
        latest_manifest = next(
            (m for _, m in versions if m.get("id") == latest), None
        )
        if latest_manifest:
            self._card_set(
                self._card_latest,
                f"v{latest_manifest.get('version','?')}  ·  {(latest_manifest.get('id') or '')[:8]}…",
                self.MINT,
            )
        elif versions:
            self._card_set(self._card_latest, "(brak wskaźnika latest)", self.ORANGE)
        else:
            self._card_set(self._card_latest, "(brak wersji)", self.FG_DIM)

        self._card_set(self._card_count, str(len(versions)), self.MINT)

        try:
            r = requests.get(MERKLE_SERVICE_URL + "/log", timeout=3)
            log_data = r.json()
            n = len(log_data.get("entries", []))
            root = (log_data.get("root") or "null")[:16] + "…"
            self._card_set(self._card_merkle_status, f"{n} wpisów  ·  root {root}", self.GREEN)
        except Exception:
            self._card_set(self._card_merkle_status, "Niedostępny", self.RED)

        # Rebuild versions list
        w = self._versions_text
        w.configure(state="normal")
        w.delete("1.0", "end")

        if not versions:
            w.insert("end", "\n  (brak wersji — użyj przycisku '+ Dodaj wersję')\n", "dim")
            w.configure(state="disabled")
            return

        w.insert("end", f"  {'WERSJA':<12} {'ID':<38} {'SHA256':<20}  ROZMIAR    PLIK\n", "hdr")
        w.insert("end", "  " + "─" * 100 + "\n", "dim")

        for version_dir, manifest in reversed(versions):
            rid   = manifest.get("id", "?")
            ver   = manifest.get("version", "?")
            sha   = (manifest.get("sha256") or "?")[:18] + "…"
            size  = manifest.get("size_bytes", 0)
            fname = manifest.get("package_name", "?")
            mark  = "  ← LATEST" if rid == latest else ""
            tag   = "latest" if rid == latest else "ver"
            line  = f"  {ver:<12} {rid:<38} {sha:<20}  {size:<10} {fname}{mark}\n"
            w.insert("end", line, tag)

        w.insert("end", "\n", "dim")
        w.insert("end", f"  Katalog: {VERSIONS_DIR}\n", "dim")
        w.configure(state="disabled")

    # ── Merkle tab ────────────────────────────────────────────────────────────
    def _refresh_merkle(self) -> None:
        w = self._merkle_text
        w.configure(state="normal")
        w.delete("1.0", "end")

        try:
            tree_r = requests.get(MERKLE_SERVICE_URL + "/merkle-tree", timeout=8)
            tree_r.raise_for_status()
            tree = tree_r.json()

            log_r = requests.get(MERKLE_SERVICE_URL + "/log", timeout=8)
            log_data = log_r.json()
            entries = log_data.get("entries", [])
        except Exception as exc:
            w.insert("end", f"Błąd połączenia z Merkle service:\n{exc}\n\n", "err")
            w.insert("end", f"URL: {MERKLE_SERVICE_URL}\n", "dim")
            w.configure(state="disabled")
            return

        leaves  = tree.get("leaves", [])
        layers  = tree.get("layers", [])
        root    = tree.get("root") or "(brak)"

        # Load versions for ID→version mapping
        ver_map = {m.get("id"): m.get("version", "?") for _, m in _load_versions()}
        latest = _latest_id()

        w.insert("end", "TRANSPARENCY LOG — Merkle Tree\n\n", "title")
        w.insert("end", f"Wpisy w logu : {len(entries)}\n", None)
        w.insert("end", f"Liście       : {len(leaves)}\n", None)
        w.insert("end", f"Poziomy      : {len(layers)}\n\n", None)

        w.insert("end", "LIŚCIE  (sha256(canonical_manifest)  →  sha256(leaf_bytes))\n", None)
        w.insert("end", "─" * 90 + "\n", "dim")
        for i, (leaf, entry) in enumerate(zip(leaves, entries)):
            rid = entry.get("id", "?")
            ver = ver_map.get(rid, "?")
            mark = "  ← LATEST" if rid == latest else ""
            is_latest = rid == latest
            tag = "hi" if is_latest else None

            prefix = "  ▸ " if is_latest else "    "
            line = f"{prefix}[{i}] v{ver:<8} id={rid[:16]}…  leaf={leaf[:32]}…{mark}\n"
            w.insert("end", line, tag or "")

        w.insert("end", "\n")
        w.insert("end", "POZIOMY\n", None)
        w.insert("end", "─" * 90 + "\n", "dim")
        for layer in layers:
            level  = layer["level"]
            hashes = layer["hashes"]
            label  = f"  Poziom {level} — {len(hashes)} węzł(ów)" + (" [ROOT]" if level == len(layers) - 1 else "")
            w.insert("end", label + "\n", "dim")
            for h in hashes:
                w.insert("end", f"      {h}\n", None)
            w.insert("end", "\n")

        w.insert("end", "KORZEŃ (Merkle root commitment)\n", "root")
        w.insert("end", f"{root}\n", "root")

        w.configure(state="disabled")

    # ── Log tab ───────────────────────────────────────────────────────────────
    def _append_log(self, line: str) -> None:
        tag = "err" if "error" in line.lower() else ("warn" if "warn" in line.lower() else "info")
        self._log.configure(state="normal")
        start = self._log.index("end")
        self._log.insert("end", line + "\n")
        self._log.tag_add(tag, start, "end-1c")
        self._log.configure(state="disabled")
        self._log.see("end")

    def _clear_log(self) -> None:
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    # ── Status polling ────────────────────────────────────────────────────────
    def _poll_status(self) -> None:
        if _srv.running:
            host = self._host_var.get().strip() or HOST
            port = self._port_var.get().strip() or str(PORT)
            self._set_status(f"● Działa  ·  http://{host}:{port}", self.GREEN)
            self._btn_start.configure(state="disabled")
            self._btn_stop.configure(state="normal")
        else:
            if self._btn_stop.cget("state") == "normal":
                # server just stopped (crashed or stopped)
                self._btn_start.configure(state="normal")
                self._btn_stop.configure(state="disabled")
                self._set_status("● Zatrzymany", self.FG_DIM)
        self.after(1500, self._poll_status)

    # ── Footer ────────────────────────────────────────────────────────────────
    def _set_status(self, text: str, color: str) -> None:
        self._status_lbl.config(text=text, fg=color)


if __name__ == "__main__":
    app = App()
    app.mainloop()
