# Multi-Layer Encryption GUI

A desktop app (Python + Tkinter) for encrypting and decrypting text with a custom multi-layer cipher. Each encryption uses a random salt, so the same text and key give a different result every time.

## How the cipher works

1. **Key expansion:** the secret key is hashed with SHA-256
2. **Round keys:** a fresh key is derived for each round from the key, round number and salt
3. **Each round:** XOR with the round key, bit scrambling, then positional shifting
4. The salt is stored with the output (Base64), so decryption needs only the key and the number of rounds

## Features

- **Encrypt** and **Decrypt** tabs, with a show/hide toggle for the key and adjustable rounds
- **Admin** tab: session log of operations and settings (minimum key length, default rounds)
- **About** tab explaining the algorithm
- Logs are saved to a local SQLite file (`encryption_system.db`, created automatically). Plaintext, ciphertext and keys are never stored, only key fingerprints.

## Run

```bash
python encryption_gui.py
```

Needs Python 3 with Tkinter (included in most installs). No other dependencies.

## Files

| Path | What it does |
|---|---|
| `encryption_gui.py` | Whole app: `AdvancedCipher` (cipher engine), `SessionDatabase` (SQLite logs and settings), `EncryptionApp` (Tkinter GUI) |

> Educational project. For real-world security, use a vetted algorithm such as AES (for example via the `cryptography` library).
