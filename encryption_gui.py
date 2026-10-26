import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64
import hashlib
import secrets
import sqlite3
import os
from datetime import datetime

# ─── CIPHER ENGINE ───────────────────────────

class AdvancedCipher:
    """
    A multi-layer encryption system combining:
    - Dynamic key expansion
    - Positional shifting
    - XOR operations
    - Bit manipulation
    - Salt for uniqueness
    """

    def __init__(self, master_key: str, rounds: int = 3):
        self.master_key = master_key
        self.rounds = max(1, rounds)
        self.expanded_key = self._expand_key(master_key)

    def _expand_key(self, key: str) -> bytes:
        return hashlib.sha256(key.encode()).digest()

    def _generate_round_key(self, round_num: int, salt: bytes) -> bytes:
        combined = self.expanded_key + salt + round_num.to_bytes(4, 'big')
        return hashlib.sha256(combined).digest()

    def _bit_scramble(self, data: bytes, key: bytes) -> bytes:
        result = bytearray()
        for i, byte in enumerate(data):
            key_byte = key[i % len(key)]
            scrambled = byte ^ key_byte
            shift = i % 8
            scrambled = ((scrambled << shift) | (scrambled >> (8 - shift))) & 0xFF
            result.append(scrambled)
        return bytes(result)

    def _bit_unscramble(self, data: bytes, key: bytes) -> bytes:
        result = bytearray()
        for i, byte in enumerate(data):
            shift = i % 8
            unscrambled = ((byte >> shift) | (byte << (8 - shift))) & 0xFF
            key_byte = key[i % len(key)]
            unscrambled = unscrambled ^ key_byte
            result.append(unscrambled)
        return bytes(result)

    def _positional_shift(self, data: bytes, key: bytes, forward: bool = True) -> bytes:
        result = bytearray()
        for i, byte in enumerate(data):
            key_val = key[i % len(key)]
            shift_amount = key_val % 256
            if not forward:
                shift_amount = -shift_amount
            result.append((byte + shift_amount) % 256)
        return bytes(result)

    def encrypt(self, plaintext: str) -> str:
        salt = secrets.token_bytes(16)
        data = plaintext.encode('utf-8')
        for round_num in range(self.rounds):
            round_key = self._generate_round_key(round_num, salt)
            data = bytes([b ^ round_key[i % len(round_key)] for i, b in enumerate(data)])
            data = self._positional_shift(data, round_key, forward=True)
            data = self._bit_scramble(data, round_key)
        encrypted_data = salt + data
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt(self, encrypted_text: str) -> str:
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            salt = encrypted_data[:16]
            data = encrypted_data[16:]
            for round_num in range(self.rounds - 1, -1, -1):
                round_key = self._generate_round_key(round_num, salt)
                data = self._bit_unscramble(data, round_key)
                data = self._positional_shift(data, round_key, forward=False)
                data = bytes([b ^ round_key[i % len(round_key)] for i, b in enumerate(data)])
            return data.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed. Invalid key or corrupted data: {e}")


# ─── DATA LAYER (SQLite session logging) ─────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encryption_system.db")


class SessionDatabase:
    """
    Local SQLite database used for session logging and configuration.
    Plaintext, ciphertext and secret keys are NEVER stored. Keys are recorded
    only as salted PBKDF2-HMAC-SHA256 fingerprints.
    """

    def __init__(self, path: str = DB_PATH):
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._create_tables()

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS EncryptionKeys (
                           key_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                           key_hash    TEXT    NOT NULL,
                           hash_salt   TEXT    NOT NULL,
                           iterations  INTEGER NOT NULL,
                           created_at  TEXT    NOT NULL)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS UserSessions (
                           session_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                           timestamp     TEXT    NOT NULL,
                           operation     TEXT    NOT NULL,
                           rounds        INTEGER NOT NULL,
                           input_length  INTEGER NOT NULL,
                           output_length INTEGER NOT NULL,
                           status        TEXT    NOT NULL,
                           key_id        INTEGER REFERENCES EncryptionKeys(key_id))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS CipherConfig (
                           config_key   TEXT PRIMARY KEY,
                           config_value TEXT NOT NULL,
                           description  TEXT)""")
        defaults = [("default_rounds", "3", "Rounds selected when the application starts"),
                    ("min_key_length", "4", "Minimum number of characters for a secret key"),
                    ("max_rounds", "10", "Maximum number of encryption rounds allowed")]
        cur.executemany("INSERT OR IGNORE INTO CipherConfig VALUES (?, ?, ?)", defaults)
        self.conn.commit()

    def _store_key_fingerprint(self, key: str) -> int:
        salt = secrets.token_bytes(16)
        iterations = 200_000
        digest = hashlib.pbkdf2_hmac("sha256", key.encode(), salt, iterations)
        cur = self.conn.execute(
            "INSERT INTO EncryptionKeys (key_hash, hash_salt, iterations, created_at) VALUES (?, ?, ?, ?)",
            (digest.hex(), salt.hex(), iterations, datetime.now().isoformat(timespec="seconds")))
        return cur.lastrowid

    def log_session(self, operation, rounds, input_length, output_length, status, key=None):
        key_id = self._store_key_fingerprint(key) if key else None
        self.conn.execute(
            "INSERT INTO UserSessions (timestamp, operation, rounds, input_length, output_length, status, key_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), operation, rounds,
             input_length, output_length, status, key_id))
        self.conn.commit()

    def get_sessions(self, limit: int = 200):
        return self.conn.execute(
            "SELECT session_id, timestamp, operation, rounds, input_length, output_length, status "
            "FROM UserSessions ORDER BY session_id DESC LIMIT ?", (limit,)).fetchall()

    def clear_sessions(self):
        self.conn.execute("DELETE FROM UserSessions")
        self.conn.execute("DELETE FROM EncryptionKeys")
        self.conn.commit()

    def get_config(self, name: str, default: str) -> str:
        row = self.conn.execute("SELECT config_value FROM CipherConfig WHERE config_key = ?",
                                (name,)).fetchone()
        return row[0] if row else default

    def set_config(self, name: str, value: str):
        self.conn.execute("UPDATE CipherConfig SET config_value = ? WHERE config_key = ?", (value, name))
        self.conn.commit()


# ─── COLOUR PALETTE (black & white / monochrome) ─────────────────────────────
BG        = "#1a1a1a"   # near-black background
PANEL     = "#262626"   # slightly lighter panels
BORDER    = "#3a3a3a"   # subtle borders
FG        = "#f0f0f0"   # primary text
FG_DIM    = "#888888"   # muted labels
ACCENT    = "#ffffff"   # pure white accent
BTN_BG    = "#333333"   # button face
BTN_HOV   = "#4a4a4a"   # button hover
BTN_ACT   = "#222222"   # button active/pressed
SUCCESS   = "#aaffaa"   # light green tint for success
ERROR     = "#ffaaaa"   # light red tint for error
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI", 13, "bold")
FONT_SUB  = ("Segoe UI", 9)


# ─── HELPER: rounded/flat button ─────────────────────────────────────────────
class FlatButton(tk.Button):
    def __init__(self, master, **kw):
        kw.setdefault("relief", "flat")
        kw.setdefault("bg", BTN_BG)
        kw.setdefault("fg", FG)
        kw.setdefault("activebackground", BTN_ACT)
        kw.setdefault("activeforeground", ACCENT)
        kw.setdefault("font", FONT_UI)
        kw.setdefault("cursor", "hand2")
        kw.setdefault("padx", 14)
        kw.setdefault("pady", 6)
        kw.setdefault("bd", 0)
        super().__init__(master, **kw)
        self.bind("<Enter>", lambda e: self.config(bg=BTN_HOV))
        self.bind("<Leave>", lambda e: self.config(bg=kw.get("bg", BTN_BG)))


# ─── MAIN APPLICATION ─────────────────────────────────────────────────────────
class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Text Encryption System")
        self.geometry("860x680")
        self.minsize(720, 580)
        self.configure(bg=BG)
        self.resizable(True, True)

        self.db = SessionDatabase()
        self.min_key_length = int(self.db.get_config("min_key_length", "4"))
        self.default_rounds = int(self.db.get_config("default_rounds", "3"))

        self._build_header()
        self._build_notebook()
        self._build_status_bar()

    # ── HEADER ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=PANEL, pady=14)
        hdr.pack(fill="x")

        tk.Label(hdr, text="🔐  Advanced Text Encryption System",
                 bg=PANEL, fg=ACCENT, font=("Segoe UI", 16, "bold")).pack()
        tk.Label(hdr, text="Legacy University Okija  ·  Department of Computer Science",
                 bg=PANEL, fg=FG_DIM, font=FONT_SUB).pack()

        # thin separator
        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x")

    # ── NOTEBOOK (tabs) ───────────────────────────────────────────────────────
    def _build_notebook(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.TNotebook",        background=BG,    borderwidth=0)
        style.configure("Dark.TNotebook.Tab",    background=PANEL, foreground=FG_DIM,
                        font=FONT_UI, padding=[16, 6])
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", BTN_HOV)],
                  foreground=[("selected", ACCENT)])

        self.nb = ttk.Notebook(self, style="Dark.TNotebook")
        self.nb.pack(fill="both", expand=True, padx=0, pady=0)

        self._tab_encrypt = self._make_encrypt_tab()
        self._tab_decrypt = self._make_decrypt_tab()
        self._tab_about   = self._make_about_tab()
        self._tab_admin   = self._make_admin_tab()

        self.nb.add(self._tab_encrypt, text="  🔒  Encrypt  ")
        self.nb.add(self._tab_decrypt, text="  🔓  Decrypt  ")
        self.nb.add(self._tab_about,   text="  ℹ️  About     ")
        self.nb.add(self._tab_admin,   text="  ⚙  Admin     ")

    # ── STATUS BAR ────────────────────────────────────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self, bg=PANEL, pady=4)
        bar.pack(fill="x", side="bottom")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", side="bottom")

        self.status_var = tk.StringVar(value="Ready.")
        self.status_lbl = tk.Label(bar, textvariable=self.status_var,
                                   bg=PANEL, fg=FG_DIM, font=FONT_SUB, anchor="w", padx=10)
        self.status_lbl.pack(side="left")

    def _set_status(self, msg: str, colour: str = FG_DIM):
        self.status_var.set(msg)
        self.status_lbl.config(fg=colour)

    # ── SHARED WIDGET HELPERS ─────────────────────────────────────────────────
    def _section(self, parent, label):
        tk.Label(parent, text=label, bg=BG, fg=FG_DIM,
                 font=FONT_SUB, anchor="w").pack(fill="x", padx=18, pady=(12, 2))

    def _key_row(self, parent):
        """Returns (frame, key_entry, rounds_spinbox)."""
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", padx=18, pady=(0, 4))

        # Key label + entry
        tk.Label(row, text="Secret Key:", bg=BG, fg=FG, font=FONT_UI).pack(side="left")
        key_var = tk.StringVar()
        key_entry = tk.Entry(row, textvariable=key_var, show="•",
                             bg=PANEL, fg=FG, insertbackground=FG,
                             relief="flat", font=FONT_UI, width=28,
                             highlightthickness=1, highlightcolor=BORDER,
                             highlightbackground=BORDER)
        key_entry.pack(side="left", padx=(6, 16))

        # Show/hide toggle
        visible = tk.BooleanVar(value=False)
        def toggle_vis():
            key_entry.config(show="" if visible.get() else "•")
        tk.Checkbutton(row, text="Show", variable=visible, command=toggle_vis,
                       bg=BG, fg=FG_DIM, selectcolor=PANEL,
                       activebackground=BG, font=FONT_SUB).pack(side="left", padx=(0, 16))

        # Rounds
        tk.Label(row, text="Rounds:", bg=BG, fg=FG, font=FONT_UI).pack(side="left")
        rounds_var = tk.IntVar(value=self.default_rounds)
        sp = tk.Spinbox(row, from_=1, to=10, textvariable=rounds_var, width=4,
                        bg=PANEL, fg=FG, buttonbackground=BTN_BG,
                        relief="flat", font=FONT_UI, insertbackground=FG)
        sp.pack(side="left", padx=(4, 0))

        return row, key_var, rounds_var

    def _text_box(self, parent, placeholder="", height=8):
        box = scrolledtext.ScrolledText(parent, height=height,
                                        bg=PANEL, fg=FG, insertbackground=FG,
                                        font=FONT_MONO, relief="flat",
                                        wrap="word", padx=8, pady=6,
                                        highlightthickness=1,
                                        highlightcolor=BORDER,
                                        highlightbackground=BORDER)
        box.pack(fill="both", expand=True, padx=18, pady=(0, 4))
        if placeholder:
            box.insert("1.0", placeholder)
            box.config(fg=FG_DIM)
            def on_focus_in(e):
                if box.get("1.0", "end-1c") == placeholder:
                    box.delete("1.0", "end")
                    box.config(fg=FG)
            def on_focus_out(e):
                if not box.get("1.0", "end-1c").strip():
                    box.insert("1.0", placeholder)
                    box.config(fg=FG_DIM)
            box.bind("<FocusIn>",  on_focus_in)
            box.bind("<FocusOut>", on_focus_out)
        return box

    def _btn_row(self, parent, buttons):
        """buttons = list of (label, command, accent?)"""
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", padx=18, pady=(4, 8))
        for label, cmd, is_accent in buttons:
            bg = ACCENT if is_accent else BTN_BG
            fg = "#000000" if is_accent else FG
            b = FlatButton(row, text=label, command=cmd, bg=bg, fg=fg)
            b.pack(side="left", padx=(0, 8))
        return row

    # ── ENCRYPT TAB ──────────────────────────────────────────────────────────
    def _make_encrypt_tab(self):
        frame = tk.Frame(self.nb, bg=BG)

        self._section(frame, "PLAIN TEXT")
        self.enc_input = self._text_box(frame, placeholder="Type or paste your text here…", height=9)

        self._section(frame, "KEY & SETTINGS")
        _, self.enc_key, self.enc_rounds = self._key_row(frame)

        self._btn_row(frame, [
            ("🔒  Encrypt", self._do_encrypt, True),
            ("🗑  Clear All", self._clear_encrypt, False),
        ])

        self._section(frame, "CIPHER TEXT  (Base64 encoded output)")
        self.enc_output = self._text_box(frame, height=7)
        self.enc_output.config(state="disabled")

        self._btn_row(frame, [
            ("📋  Copy Ciphertext", self._copy_enc_output, False),
            ("➡  Send to Decrypt tab", self._send_to_decrypt, False),
        ])

        return frame

    # ── DECRYPT TAB ──────────────────────────────────────────────────────────
    def _make_decrypt_tab(self):
        frame = tk.Frame(self.nb, bg=BG)

        self._section(frame, "CIPHER TEXT  (paste Base64 encoded text)")
        self.dec_input = self._text_box(frame, placeholder="Paste encrypted (Base64) text here…", height=9)

        self._section(frame, "KEY & SETTINGS")
        _, self.dec_key, self.dec_rounds = self._key_row(frame)

        self._btn_row(frame, [
            ("🔓  Decrypt", self._do_decrypt, True),
            ("🗑  Clear All", self._clear_decrypt, False),
        ])

        self._section(frame, "PLAIN TEXT  (decrypted output)")
        self.dec_output = self._text_box(frame, height=7)
        self.dec_output.config(state="disabled")

        self._btn_row(frame, [
            ("📋  Copy Plaintext", self._copy_dec_output, False),
        ])

        return frame

    # ── ABOUT TAB ────────────────────────────────────────────────────────────
    def _make_about_tab(self):
        frame = tk.Frame(self.nb, bg=BG)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # Canvas + scrollbar
        canvas = tk.Canvas(frame, bg=BG, highlightthickness=0, bd=0)
        scrollbar = tk.Scrollbar(frame, orient="vertical", command=canvas.yview,
                                 bg=PANEL, troughcolor=BG, activebackground=BTN_HOV)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Inner frame lives inside canvas
        inner = tk.Frame(canvas, bg=BG)
        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        # Make inner frame always match canvas width
        def on_canvas_resize(e):
            canvas.itemconfig(inner_id, width=e.width)
        canvas.bind("<Configure>", on_canvas_resize)

        # Update scroll region whenever inner frame changes size
        def on_inner_resize(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", on_inner_resize)

        # Mouse wheel scrolling
        def on_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", on_mousewheel)

        # ── Content ───────────────────────────────────────────────────────
        lines = [
            ("Advanced Text Encryption System", ("Segoe UI", 17, "bold"), ACCENT, 20),
            ("Legacy University Okija — Department of Computer Science", FONT_SUB, FG_DIM, 6),
            ("", FONT_SUB, FG, 18),
            ("HOW THE CIPHER WORKS", ("Segoe UI", 10, "bold"), FG_DIM, 0),
            ("", FONT_SUB, FG, 4),
            ("This system uses a custom multi-layer cipher applied on each encryption round:", FONT_UI, FG, 0),
            ("", FONT_SUB, FG, 8),
            ("  Layer 1 — XOR Operation", ("Segoe UI", 10, "bold"), ACCENT, 0),
            ("  Each byte of plaintext is XORed with the round key, making the output completely key-dependent.", FONT_UI, FG, 0),
            ("", FONT_SUB, FG, 8),
            ("  Layer 2 — Positional Shift", ("Segoe UI", 10, "bold"), ACCENT, 0),
            ("  Bytes are shifted by amounts derived from the key and their position, adding key-dependent diffusion.", FONT_UI, FG, 0),
            ("", FONT_SUB, FG, 8),
            ("  Layer 3 — Bit Scrambling", ("Segoe UI", 10, "bold"), ACCENT, 0),
            ("  Each byte is XORed again and its bits are rotated by an amount that depends on its position, further mixing the bits of every byte.", FONT_UI, FG, 0),
            ("", FONT_SUB, FG, 8),
            ("  Salt", ("Segoe UI", 10, "bold"), ACCENT, 0),
            ("  A 16-byte cryptographic random salt is prepended before encryption, ensuring that encrypting the same text twice always gives different ciphertext.", FONT_UI, FG, 0),
            ("", FONT_SUB, FG, 20),
            ("KEY GUIDELINES", ("Segoe UI", 10, "bold"), FG_DIM, 0),
            ("  •  Use at least 12 characters for a strong key", FONT_UI, FG, 4),
            ("  •  Mix uppercase, lowercase, digits, and symbols", FONT_UI, FG, 4),
            ("  •  Always use the same key and rounds to decrypt", FONT_UI, FG, 4),
            ("  •  Never share your key over an insecure channel", FONT_UI, FG, 4),
            ("  •  If you lose your key, the data cannot be recovered", FONT_UI, FG, 4),
            ("", FONT_SUB, FG, 20),
            ("ROUNDS EXPLAINED", ("Segoe UI", 10, "bold"), FG_DIM, 0),
            ("  •  1–2 rounds  →  Fast, suitable for low-sensitivity data", FONT_UI, FG, 4),
            ("  •  3 rounds    →  Default, good balance of speed and security", FONT_UI, FG, 4),
            ("  •  5–10 rounds →  Strongest, slightly slower on large texts", FONT_UI, FG, 4),
            ("", FONT_SUB, FG, 24),
            ("Implemented in Python 3   ·   GUI built with Tkinter", FONT_SUB, FG_DIM, 0),
            ("", FONT_SUB, FG, 6),
        ]

        for text, font, colour, pady_top in lines:
            tk.Label(inner, text=text, bg=BG, fg=colour, font=font,
                     justify="left", anchor="w", wraplength=0).pack(
                fill="x", anchor="w", padx=40, pady=(pady_top, 0))

        return frame

    # ── ADMIN TAB (session log + system configuration) ───────────────────────
    def _make_admin_tab(self):
        frame = tk.Frame(self.nb, bg=BG)

        self._section(frame, "SESSION LOG  (no text or keys are stored)")
        style = ttk.Style()
        style.configure("Dark.Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=FG, font=FONT_SUB, rowheight=22, borderwidth=0)
        style.configure("Dark.Treeview.Heading", background=BTN_BG, foreground=FG,
                        font=FONT_SUB, relief="flat")
        cols = ("id", "time", "operation", "rounds", "in", "out", "status")
        heads = ("ID", "Timestamp", "Operation", "Rounds", "Input chars", "Output chars", "Status")
        widths = (40, 150, 90, 60, 90, 95, 80)
        holder = tk.Frame(frame, bg=BG)
        holder.pack(fill="both", expand=True, padx=18, pady=(0, 4))
        self.log_tree = ttk.Treeview(holder, columns=cols, show="headings",
                                     style="Dark.Treeview", height=10)
        for c, h, w in zip(cols, heads, widths):
            self.log_tree.heading(c, text=h)
            self.log_tree.column(c, width=w, anchor="center")
        sb = ttk.Scrollbar(holder, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log_tree.pack(side="left", fill="both", expand=True)

        self._btn_row(frame, [
            ("🔄  Refresh Log", self._refresh_log, False),
            ("🗑  Clear Log", self._clear_log, False),
        ])

        self._section(frame, "SYSTEM CONFIGURATION")
        row = tk.Frame(frame, bg=BG)
        row.pack(fill="x", padx=18, pady=(0, 4))
        tk.Label(row, text="Default rounds:", bg=BG, fg=FG, font=FONT_UI).pack(side="left")
        self.cfg_rounds = tk.IntVar(value=self.default_rounds)
        tk.Spinbox(row, from_=1, to=10, textvariable=self.cfg_rounds, width=4,
                   bg=PANEL, fg=FG, buttonbackground=BTN_BG, relief="flat",
                   font=FONT_UI, insertbackground=FG).pack(side="left", padx=(4, 20))
        tk.Label(row, text="Minimum key length:", bg=BG, fg=FG, font=FONT_UI).pack(side="left")
        self.cfg_minkey = tk.IntVar(value=self.min_key_length)
        tk.Spinbox(row, from_=4, to=32, textvariable=self.cfg_minkey, width=4,
                   bg=PANEL, fg=FG, buttonbackground=BTN_BG, relief="flat",
                   font=FONT_UI, insertbackground=FG).pack(side="left", padx=(4, 0))

        self._btn_row(frame, [("💾  Save Configuration", self._save_config, True)])

        self._refresh_log()
        return frame

    def _refresh_log(self):
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        for row in self.db.get_sessions():
            self.log_tree.insert("", "end", values=row)

    def _clear_log(self):
        if messagebox.askyesno("Clear Log", "Delete all session log entries?"):
            self.db.clear_sessions()
            self._refresh_log()
            self._set_status("Session log cleared.")

    def _save_config(self):
        try:
            rounds = int(self.cfg_rounds.get())
            min_key = int(self.cfg_minkey.get())
        except (tk.TclError, ValueError):
            messagebox.showwarning("Invalid Value", "Please enter whole numbers only.")
            return
        if not (1 <= rounds <= 10) or not (4 <= min_key <= 32):
            messagebox.showwarning("Invalid Value",
                                   "Rounds must be 1–10 and minimum key length 4–32.")
            return
        self.db.set_config("default_rounds", str(rounds))
        self.db.set_config("min_key_length", str(min_key))
        self.default_rounds, self.min_key_length = rounds, min_key
        self._set_status("✅  Configuration saved.", SUCCESS)


    # ── ACTIONS ───────────────────────────────────────────────────────────────
    def _get_plain_text(self, box, placeholder):
        t = box.get("1.0", "end-1c")
        return "" if t == placeholder else t

    def _do_encrypt(self):
        text = self._get_plain_text(self.enc_input, "Type or paste your text here…")
        key  = self.enc_key.get().strip()
        rounds = self.enc_rounds.get()

        if not text:
            messagebox.showwarning("Empty Input", "Please enter some text to encrypt.")
            return
        if not key:
            messagebox.showwarning("No Key", "Please enter a secret key.")
            return
        if len(key) < self.min_key_length:
            messagebox.showwarning("Key Too Short",
                                   f"Key must be at least {self.min_key_length} characters.")
            return

        try:
            cipher = AdvancedCipher(master_key=key, rounds=rounds)
            result = cipher.encrypt(text)
            self.enc_output.config(state="normal")
            self.enc_output.delete("1.0", "end")
            self.enc_output.insert("1.0", result)
            self.enc_output.config(state="disabled")
            self.db.log_session("ENCRYPT", rounds, len(text), len(result), "SUCCESS", key)
            self._refresh_log()
            self._set_status(f"✅  Encrypted successfully  ({rounds} round{'s' if rounds>1 else ''}, {len(text)} chars → {len(result)} chars ciphertext)", SUCCESS)
        except Exception as e:
            self.db.log_session("ENCRYPT", rounds, len(text), 0, "FAILED")
            messagebox.showerror("Encryption Error", str(e))
            self._set_status(f"❌  Encryption failed: {e}", ERROR)

    def _do_decrypt(self):
        text  = self._get_plain_text(self.dec_input, "Paste encrypted (Base64) text here…").strip()
        key   = self.dec_key.get().strip()
        rounds = self.dec_rounds.get()

        if not text:
            messagebox.showwarning("Empty Input", "Please paste ciphertext to decrypt.")
            return
        if not key:
            messagebox.showwarning("No Key", "Please enter the secret key used during encryption.")
            return

        try:
            cipher = AdvancedCipher(master_key=key, rounds=rounds)
            result = cipher.decrypt(text)
            self.dec_output.config(state="normal")
            self.dec_output.delete("1.0", "end")
            self.dec_output.insert("1.0", result)
            self.dec_output.config(state="disabled")
            self.db.log_session("DECRYPT", rounds, len(text), len(result), "SUCCESS", key)
            self._refresh_log()
            self._set_status(f"✅  Decrypted successfully  ({len(result)} characters recovered)", SUCCESS)
        except ValueError as e:
            self.db.log_session("DECRYPT", rounds, len(text), 0, "FAILED")
            self._refresh_log()
            messagebox.showerror("Decryption Failed",
                                 "Could not decrypt the text.\n\nPossible reasons:\n"
                                 "• Wrong secret key\n• Wrong number of rounds\n• Corrupted ciphertext")
            self._set_status("❌  Decryption failed — check key and rounds", ERROR)

    def _clear_encrypt(self):
        self.enc_input.config(fg=FG)
        self.enc_input.delete("1.0", "end")
        self.enc_output.config(state="normal")
        self.enc_output.delete("1.0", "end")
        self.enc_output.config(state="disabled")
        self.enc_key.set("")
        self._set_status("Cleared.")

    def _clear_decrypt(self):
        self.dec_input.config(fg=FG)
        self.dec_input.delete("1.0", "end")
        self.dec_output.config(state="normal")
        self.dec_output.delete("1.0", "end")
        self.dec_output.config(state="disabled")
        self.dec_key.set("")
        self._set_status("Cleared.")

    def _copy_enc_output(self):
        text = self.enc_output.get("1.0", "end-1c")
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("📋  Ciphertext copied to clipboard.")
        else:
            messagebox.showinfo("Nothing to Copy", "Encrypt something first.")

    def _copy_dec_output(self):
        text = self.dec_output.get("1.0", "end-1c")
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("📋  Plaintext copied to clipboard.")
        else:
            messagebox.showinfo("Nothing to Copy", "Decrypt something first.")

    def _send_to_decrypt(self):
        text = self.enc_output.get("1.0", "end-1c")
        if not text:
            messagebox.showinfo("Nothing to Send", "Encrypt something first.")
            return
        self.dec_input.config(fg=FG)
        self.dec_input.delete("1.0", "end")
        self.dec_input.insert("1.0", text)
        # also copy key & rounds
        self.dec_key.set(self.enc_key.get())
        self.dec_rounds.set(self.enc_rounds.get())
        self.nb.select(1)   # switch to decrypt tab
        self._set_status("➡  Ciphertext transferred to Decrypt tab.")


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
