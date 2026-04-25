# cipher [![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

CLI file encryption tool based on **AES-256-GCM** and **PBKDF2-SHA256**.

## Dependencies

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

### Build the wheel locally

```bash
# generates dist/cipher-X.X.X-py3-none-any.whl
uv build
```

---

## Commands reference

### encrypt

```bash
cipher encrypt <file>
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

---

## Security

| Component  | Choice          | Why                                         |
| ---------- | --------------- | ------------------------------------------- |
| Encryption | AES-256-GCM     | Authenticated (integrity + confidentiality) |
| KDF        | PBKDF2-SHA256   | NIST standard, slows brute-force            |
| Iterations | 480,000         | NIST 2023 recommendation                    |
| Salt       | 32 random bytes | Protects against rainbow tables             |
| Nonce      | 12 random bytes | 96 bits = GCM standard                      |

---

## Feedback

Feedback are welcome! Feel free to open an [issue](https://codeberg.org/GautierPicon/cipher/issues) or a [pull request](https://codeberg.org/GautierPicon/cipher/pulls) on the Codeberg repository.
