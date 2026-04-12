"""
file-cipher — File encryption via AES-256-GCM
==============================================
Usage:
    cipher encrypt secret.txt            # encrypt → secret.txt.enc
    cipher decrypt secret.txt.enc        # decrypt → secret.txt
    cipher encrypt doc.pdf -o safe.enc   # custom output
    cipher info safe.enc                 # display metadata
"""

import os
import struct
import hashlib
import secrets
import typer
from pathlib import Path
from typing import Optional
from getpass import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="cipher",
    help="🔐 AES-256-GCM file encryption",
    add_completion=False,
)
console = Console()

# ── .enc format constants ────────────────────────────────────────────────────
MAGIC       = b"CIPHER01"   # header to identify our files
SALT_SIZE   = 32            # bytes for the PBKDF2 salt
NONCE_SIZE  = 12            # bytes for the AES-GCM nonce (96 bits)
PBKDF2_ITER = 480_000       # PBKDF2 iterations (NIST 2023 recommendation)
KEY_SIZE    = 32            # AES-256 → 32-byte key

# Binary header format:
#   MAGIC (8) | iterations (4, big-endian) | salt (32) | nonce (12)
HEADER_FMT  = f">8sI{SALT_SIZE}s{NONCE_SIZE}s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)   # 56 bytes


# ── Cryptographic functions ──────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITER) -> bytes:
    """Derives an AES-256 key from a password via PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def _encrypt_data(plaintext: bytes, password: str, filename: str) -> bytes:
    """Encrypts data and returns the full stream (header + ciphertext).
    The original filename is embedded inside the encrypted payload.
    Payload format: [4 bytes: name length] + [name bytes] + [file content]
    """
    salt  = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key   = _derive_key(password, salt)

    name_bytes = filename.encode()
    payload    = struct.pack(">I", len(name_bytes)) + name_bytes + plaintext

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload, None)

    header = struct.pack(HEADER_FMT, MAGIC, PBKDF2_ITER, salt, nonce)
    return header + ciphertext


def _decrypt_data(blob: bytes, password: str) -> tuple[bytes, str]:
    """Decrypts a stream produced by _encrypt_data.
    Returns (file content, original filename).
    """
    if len(blob) < HEADER_SIZE:
        raise ValueError("File too short or corrupted.")

    magic, iterations, salt, nonce = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])

    if magic != MAGIC:
        raise ValueError(
            "This file was not encrypted by file-cipher (invalid magic)."
        )

    key        = _derive_key(password, salt, iterations)
    aesgcm     = AESGCM(key)
    ciphertext = blob[HEADER_SIZE:]

    try:
        payload = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Wrong password or file has been tampered with.")

    name_len = struct.unpack(">I", payload[:4])[0]
    filename = payload[4:4 + name_len].decode()
    content  = payload[4 + name_len:]
    return content, filename


# ── UI helpers ───────────────────────────────────────────────────────────────

def _ask_password(confirm: bool = False) -> str:
    pwd = getpass("🔑 Password: ")
    if not pwd:
        console.print("[red]Password cannot be empty.[/red]")
        raise typer.Exit(1)
    if confirm:
        pwd2 = getpass("🔑 Confirm:  ")
        if pwd != pwd2:
            console.print("[red]Passwords do not match.[/red]")
            raise typer.Exit(1)
    return pwd


def _sizeof_fmt(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:,.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


# ── CLI commands ──────────────────────────────────────────────────────────────

@app.command()
def encrypt(
    file: Path = typer.Argument(..., help="File to encrypt", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite if destination exists"),
):
    """🔒 Encrypt a file with AES-256-GCM."""
    dest = output or file.with_suffix(".enc")

    if dest.exists() and not overwrite:
        console.print(f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]")
        raise typer.Exit(1)

    console.print(Panel(f"[bold]Encrypting[/bold] [cyan]{file}[/cyan]", expand=False))
    password = _ask_password(confirm=True)

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), console=console, transient=True
    ) as progress:
        task = progress.add_task("Deriving key…", total=3)
        plaintext = file.read_bytes()

        progress.update(task, advance=1, description="AES-GCM encryption…")
        encrypted = _encrypt_data(plaintext, password, file.name)

        progress.update(task, advance=1, description="Writing…")
        dest.write_bytes(encrypted)
        progress.update(task, advance=1, description="Done!")

    sha256 = hashlib.sha256(encrypted).hexdigest()[:16]

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[dim]Source[/dim]",    str(file),                f"[dim]{_sizeof_fmt(file.stat().st_size)}[/dim]")
    table.add_row("[dim]Output[/dim]",    str(dest),                f"[dim]{_sizeof_fmt(dest.stat().st_size)}[/dim]")
    table.add_row("[dim]Algorithm[/dim]", "AES-256-GCM + PBKDF2",  "")
    table.add_row("[dim]SHA-256[/dim]",   f"[dim]{sha256}…[/dim]", "")

    console.print(table)
    console.print(f"\n[green]✓ File successfully encrypted → {dest}[/green]")


@app.command()
def decrypt(
    file: Path = typer.Argument(..., help=".enc file to decrypt", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite if destination exists"),
):
    """🔓 Decrypt a file produced by 'cipher encrypt'."""
    if output:
        dest: Optional[Path] = output
        if dest.exists() and not overwrite:
            console.print(f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]")
            raise typer.Exit(1)
    else:
        dest = None

    console.print(Panel(f"[bold]Decrypting[/bold] [cyan]{file}[/cyan]", expand=False))
    password = _ask_password(confirm=False)

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        console=console, transient=True
    ) as progress:
        task = progress.add_task("Reading file…", total=None)
        blob = file.read_bytes()

        progress.update(task, description="Deriving key & decrypting…")
        try:
            plaintext, original_name = _decrypt_data(blob, password)
        except ValueError as exc:
            console.print(f"\n[red]✗ Failed: {exc}[/red]")
            raise typer.Exit(1)

        if not output:
            dest = file.parent / original_name
            if dest.exists() and not overwrite:
                console.print(f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]")
                raise typer.Exit(1)
        elif Path(output).suffix != Path(original_name).suffix:
            console.print(f"[yellow]⚠ Original file was '{original_name}' — saving as '{output.name}' instead.[/yellow]")

        progress.update(task, description="Writing…")
        dest.write_bytes(plaintext)

    console.print(f"[green]✓ File successfully decrypted → {dest}[/green]")
    console.print(f"   Size: {_sizeof_fmt(dest.stat().st_size)}")


@app.command()
def info(
    file: Path = typer.Argument(..., help=".enc file to inspect", exists=True),
):
    """ℹ️  Display metadata of an encrypted file (without decrypting it)."""
    blob = file.read_bytes()

    if len(blob) < HEADER_SIZE:
        console.print("[red]File too short to be a cipher file.[/red]")
        raise typer.Exit(1)

    magic, iterations, salt, nonce = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])

    if magic != MAGIC:
        console.print("[red]This file was not produced by file-cipher.[/red]")
        raise typer.Exit(1)

    payload_size = len(blob) - HEADER_SIZE
    sha256_full  = hashlib.sha256(blob).hexdigest()

    table = Table(title=f"📄 {file.name}", show_header=False, box=None, padding=(0, 2))
    table.add_row("[bold]Format[/bold]",       magic.decode())
    table.add_row("[bold]Algorithm[/bold]",    "AES-256-GCM")
    table.add_row("[bold]KDF[/bold]",          f"PBKDF2-SHA256 ({iterations:,} iterations)")
    table.add_row("[bold]Salt (hex)[/bold]",   salt.hex())
    table.add_row("[bold]Nonce (hex)[/bold]",  nonce.hex())
    table.add_row("[bold]Total size[/bold]",   _sizeof_fmt(len(blob)))
    table.add_row("[bold]Payload size[/bold]", _sizeof_fmt(payload_size))
    table.add_row("[bold]SHA-256[/bold]",      sha256_full)

    console.print(table)


if __name__ == "__main__":
    app()