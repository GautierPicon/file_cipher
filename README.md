# cipher [![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

CLI file encryption tool based on **AES-256-GCM** and **Argon2id**.

## Dependencies

- [`argon2-cffi`](https://argon2-cffi.readthedocs.io) — Argon2id key derivation
- [`cryptography`](https://cryptography.io) — cryptographic primitives
- [`typer`](https://typer.tiangolo.com) — CLI interface
- [`rich`](https://rich.readthedocs.io) — terminal display

---

## Install cipher on your machine

Download the latest `.whl` from the [releases page](https://codeberg.org/GautierPicon/cipher/releases), then:

```bash
# Install pipx if you don't have it
pip install pipx

# Install cipher
pipx install "cipher @ file:///path/to/cipher-X.X.X-py3-none-any.whl"

# cipher is now available globally
cipher --help
```

### Update to a newer version

Download the new `.whl` from the releases page, then:

```bash
pipx install --force "cipher @ file:///path/to/cipher-X.X.X-py3-none-any.whl"
```

### Uninstall

```bash
pipx uninstall cipher
```

---

## Development setup

### Clone the project

```bash
git clone https://codeberg.org/GautierPicon/cipher.git
cd cipher
```

### Install dependencies and create environment with uv

```bash
uv sync
```

### Run via uv

```bash
uv run cipher --help
```

### Test your changes

```bash
uv run pytest
```

### Build the wheel locally

```bash
# generates dist/cipher-X.X.X-py3-none-any.whl
uv build
```

---

## Commands reference

### encrypt

```bash
cipher encrypt <file> [<file2> ...]
cipher encrypt <file> --genpass
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

### verify

```bash
cipher verify <file.enc>
```

### help

```bash
cipher --help
cipher encrypt --help
cipher decrypt --help
cipher verify --help
```

---

## Usage

### Encrypt a file

```bash
# Encrypt secret.txt → secret.enc
cipher encrypt secret.txt

# Encrypt rapport.pdf and name the output vault.enc
cipher encrypt rapport.pdf -o vault.enc

# Encrypt a folder
cipher encrypt my-folder/
```

### Encrypt multiple files at once

```bash
# Encrypt several files in one command — one password prompt for all
cipher encrypt file1.txt file2.pdf my-folder/

# With --overwrite if the .enc files already exist
cipher encrypt file1.txt file2.pdf --overwrite
```

> `-o` / `--output` cannot be used when encrypting multiple files.

### Encrypt with a generated password

```bash
# Generate a strong random password, use it to encrypt, and copy it to clipboard
cipher encrypt secret.txt --genpass
```

> ⚠ The generated password is displayed once and cannot be recovered. Store it in a password manager.

### Decrypt a file

```bash
# Decrypt secret.enc → restores original filename automatically
cipher decrypt secret.enc

# Decrypt and choose a custom output name
cipher decrypt vault.enc -o restored_report.pdf
```

### Verify a file

```bash
# Verify integrity and password without writing anything to disk
cipher verify secret.enc
```

`verify` decrypts every chunk in memory and checks the AES-GCM authentication tag. It confirms that:
- the password is correct,
- the file has not been tampered with or truncated.

No output file is ever created.

---

## Platform support

cipher runs on **macOS, Linux, and Windows**.

| Feature | macOS | Linux | Windows |
|---|---|---|---|
| Encryption / Decryption | ✓ | ✓ | ✓ |
| Verify | ✓ | ✓ | ✓ |
| Clipboard (`--genpass`) | `pbcopy` | `xclip` / `xsel` / `wl-copy` | `clip` |
| File permissions (`chmod 600`) | ✓ | ✓ | skipped (no-op on NTFS) |
| Directory encryption | pipe | pipe | temp file (pipes are blocking on Windows) |

---

## Security

| Component      | Choice              | Why                                                      |
| -------------- | ------------------- | -------------------------------------------------------- |
| Encryption     | AES-256-GCM         | Authenticated encryption (integrity + confidentiality)   |
| KDF            | Argon2id            | GPU/ASIC-resistant; OWASP & RFC 9106 recommendation      |
| KDF parameters | t=3, m=64 MiB, p=4  | OWASP 2024 interactive profile                           |
| Salt           | 32 random bytes     | Unique per file; protects against rainbow tables         |
| Nonce          | 64-bit random + 32-bit counter | Per-chunk; avoids reuse across files and chunks |
| File format    | CIPHER02            | Self-contained header stores all KDF parameters          |

### Format CIPHER02

Each `.enc` file is self-contained: the header embeds the magic bytes, all
Argon2id parameters, a 32-byte salt, and a 12-byte base nonce. This means
cipher can always re-derive the correct key even if the default parameters
change in a future version.

Chunks are encrypted individually with AES-256-GCM. Each chunk has its own
nonce derived from the base nonce, so a truncated or reordered file is
detected immediately. The filename is authenticated inside the first chunk.

---

## Feedback

Feedback is welcome! Feel free to open an [issue](https://codeberg.org/GautierPicon/cipher/issues) or a [pull request](https://codeberg.org/GautierPicon/cipher/pulls) on the Codeberg repository.