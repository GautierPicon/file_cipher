# file-cipher [![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

CLI file encryption tool based on **AES-256-GCM** and **PBKDF2-SHA256**.

## Dependencies

- [`cryptography`](https://cryptography.io) — cryptographic primitives
- [`typer`](https://typer.tiangolo.com) — CLI interface
- [`rich`](https://rich.readthedocs.io) — terminal display

---

## Install cipher on your machine

Download the latest `.whl` from the [releases page](https://codeberg.org/GautierPicon/file_cipher/releases), then:

```bash
# Install pipx if you don't have it
pip install pipx

# Install cipher
pipx install "file-cipher @ file:///path/to/file_cipher-X.X.X-py3-none-any.whl"

# cipher is now available globally
cipher --help
```

### Update to a newer version

Download the new `.whl` from the releases page, then:

```bash
pipx install --force "file-cipher @ file:///path/to/file_cipher-X.X.X-py3-none-any.whl"
```

### Uninstall

```bash
pipx uninstall file-cipher
```

---

## Development setup

### Clone the project

```bash
git clone https://codeberg.org/GautierPicon/file_cipher.git 
cd file-cipher
```

### Install dependencies and create environment with uv

```bash
uv sync
```

### Run via uv

```bash
uv run cipher --help
```

### Build the wheel locally

```bash
# generates dist/file_cipher-X.X.X-py3-none-any.whl
uv build
```

---

## Commands reference

### encrypt
```bash
cipher encrypt <file>
cipher encrypt <file> -o <output>
cipher encrypt <file> --overwrite
cipher encrypt <file> -o <output> --overwrite
```

### decrypt
```bash
cipher decrypt <file.enc>
cipher decrypt <file.enc> -o <output>
cipher decrypt <file.enc> --overwrite
cipher decrypt <file.enc> -o <output> --overwrite
```

### genpass
```bash
cipher genpass
cipher genpass --length <length>
cipher genpass --no-copy
```

### info
```bash
cipher info <file.enc>
```

### help
```bash
cipher --help
cipher encrypt --help
cipher decrypt --help
cipher info --help
cipher genpass --help
```

---

## Usage

### Generate a strong password
```bash
# Generate a 20-character password and copy it to clipboard
cipher genpass

# Generate a longer password
cipher genpass --length <value>
```

### Encrypt a file
```bash
# Encrypt secret.txt → secret.enc
cipher encrypt secret.txt

# Encrypt rapport.pdf and name the output vault.enc
cipher encrypt rapport.pdf -o vault.enc
```

### Decrypt a file
```bash
# Decrypt secret.enc → restores original filename automatically
cipher decrypt secret.enc

# Decrypt and choose a custom output name
cipher decrypt vault.enc -o restored_report.pdf
```

### Inspect an encrypted file (without decrypting)
```bash
cipher info secret.enc
```

---

## `.enc` file format

```
┌──────────────────────────────────────────────────┐
│ MAGIC     (8 bytes)   "CIPHER01"                 │
│ ITERATIONS(4 bytes)   PBKDF2 iteration count     │
│ SALT      (32 bytes)  random salt                │
│ NONCE     (12 bytes)  AES-GCM nonce              │
│ CIPHERTEXT + TAG GCM  (rest of file)             │
└──────────────────────────────────────────────────┘
```

The original filename is stored inside the encrypted payload — it is invisible without the password and automatically restored on decryption.

---

## Security

| Component | Choice | Why |
|-----------|--------|-----|
| Encryption | AES-256-GCM | Authenticated (integrity + confidentiality) |
| KDF | PBKDF2-SHA256 | NIST standard, slows brute-force |
| Iterations | 480,000 | NIST 2023 recommendation |
| Salt | 32 random bytes | Protects against rainbow tables |
| Nonce | 12 random bytes | 96 bits = GCM standard |

---

## Feedback

Feedback are welcome! Feel free to open an [issue](https://codeberg.org/GautierPicon/file_cipher/issues) or a [pull request](https://codeberg.org/GautierPicon/file_cipher/pulls) on the Codeberg repository.