import math
import os
import secrets
import string
import struct
import subprocess

import typer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

app = typer.Typer(
    name="cipher",
    help="🔐 AES-256-GCM file encryption",
    add_completion=False,
)
console = Console()

MAGIC = b"CIPHER02"
SALT_SIZE = 32
NONCE_SIZE = 12
PBKDF2_ITER = 480_000
KEY_SIZE = 32
CHUNK_SIZE = 1024 * 1024
STREAMING_THRESHOLD = 50 * 1024 * 1024

HEADER_FMT = f">8sI{SALT_SIZE}s{NONCE_SIZE}sQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def _derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITER) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def _encrypt_data(plaintext: bytes, password: str, filename: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = _derive_key(password, salt)

    name_bytes = filename.encode()
    payload = struct.pack(">I", len(name_bytes)) + name_bytes + plaintext

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload, None)

    header = struct.pack(HEADER_FMT, MAGIC, PBKDF2_ITER, salt, nonce, len(plaintext))
    return header + ciphertext


def _decrypt_data(blob: bytes, password: str) -> tuple[bytes, str]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(blob) < HEADER_SIZE:
        raise ValueError("File too short or corrupted.")

    magic, iterations, salt, nonce, original_size = struct.unpack(
        HEADER_FMT, blob[:HEADER_SIZE]
    )

    if magic != MAGIC:
        raise ValueError("This file was not encrypted by file-cipher (invalid magic).")

    key = _derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    ciphertext = blob[HEADER_SIZE:]

    try:
        payload = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Wrong password or file has been tampered with.")

    name_len = struct.unpack(">I", payload[:4])[0]
    filename = payload[4 : 4 + name_len].decode()
    content = payload[4 + name_len :]
    return content, filename


def _encrypt_file_streaming(in_path: Path, password: str, dest: Path) -> int:
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = _derive_key(password, salt)

    total_size = in_path.stat().st_size

    header = struct.pack(HEADER_FMT, MAGIC, PBKDF2_ITER, salt, nonce, total_size)
    dest.write_bytes(header)

    ctr = 0
    with open(in_path, "rb") as fin, open(dest, "ab") as fout:
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break

            counter = struct.pack(">QQ", 0, ctr)
            ctr += 1

            cipher = Cipher(algorithms.AES(key), modes.CTR(counter))
            encryptor = cipher.encryptor()
            encrypted_chunk = encryptor.update(chunk)

            fout.write(encrypted_chunk)

    return total_size


def _decrypt_file_streaming(in_path: Path, password: str, dest: Path) -> int:
    with open(in_path, "rb") as fin:
        header = fin.read(HEADER_SIZE)
        magic, iterations, salt, nonce, original_size = struct.unpack(
            HEADER_FMT, header
        )

    if magic != MAGIC:
        raise ValueError("This file was not encrypted by file-cipher (invalid magic).")

    key = _derive_key(password, salt, iterations)

    ctr = 0
    with open(in_path, "rb") as fin, open(dest, "wb") as fout:
        fin.seek(HEADER_SIZE)
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break

            counter = struct.pack(">QQ", 0, ctr)
            ctr += 1

            cipher = Cipher(algorithms.AES(key), modes.CTR(counter))
            decryptor = cipher.decryptor()
            decrypted_chunk = decryptor.update(chunk)

            fout.write(decrypted_chunk)

    return original_size


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


def _check_password_strength(password: str) -> tuple[bool, str]:
    issues = []

    if len(password) < 12:
        issues.append("too short (min 12 characters)")

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*-_=+?" for c in password)

    if not has_upper:
        issues.append("no uppercase")
    if not has_lower:
        issues.append("no lowercase")
    if not has_digit:
        issues.append("no digit")
    if not has_special:
        issues.append("no special character")

    common = [
        "password",
        "admin",
        "123456",
        "qwerty",
        "letmein",
        "welcome",
    ]
    if password.lower() in common:
        issues.append("common password")

    if issues:
        return False, f"[yellow]Weak password: {', '.join(issues)}[/yellow]"
    return True, ""


def _sizeof_fmt(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:,.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


@app.command()
def encrypt(
    file: Path = typer.Argument(..., help="File to encrypt", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file"),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Overwrite if destination exists"
    ),
):
    """🔒 Encrypt a file with AES-256-GCM."""
    dest = output or file.with_suffix(".enc")

    if dest.exists() and not overwrite:
        console.print(
            f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]"
        )
        raise typer.Exit(1)

    console.print(Panel(f"[bold]Encrypting[/bold] [cyan]{file}[/cyan]", expand=False))
    password = _ask_password(confirm=True)

    while True:
        strong, warning = _check_password_strength(password)
        if warning:
            console.print(f"  {warning}")
            confirm = console.input("  [dim]Continue anyway? (y/n): [/dim]")
            if confirm.lower() in ("y", "yes"):
                break
            password = _ask_password(confirm=True)
        else:
            break

    file_size = file.stat().st_size
    is_streaming = file_size > STREAMING_THRESHOLD

    if is_streaming:
        console.print(
            f"  [dim]Large file detected - using streaming mode ({_sizeof_fmt(file_size)})[/dim]"
        )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Processing...", total=4)

        if is_streaming:
            progress.update(task, advance=1, description="Deriving key…")
            _encrypt_file_streaming(file, password, dest)
            progress.update(task, advance=3, description="Done!")
        else:
            progress.update(task, advance=1, description="Reading…")
            plaintext = file.read_bytes()

            progress.update(task, advance=1, description="Encrypting…")
            encrypted = _encrypt_data(plaintext, password, file.name)

            progress.update(task, advance=1, description="Writing…")
            dest.write_bytes(encrypted)
            progress.update(task, advance=1, description="Done!")

    sha256 = hashlib.sha256(dest.read_bytes()).hexdigest()[:16]

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row(
        "[dim]Source[/dim]", str(file), f"[dim]{_sizeof_fmt(file.stat().st_size)}[/dim]"
    )
    table.add_row(
        "[dim]Output[/dim]", str(dest), f"[dim]{_sizeof_fmt(dest.stat().st_size)}[/dim]"
    )
    table.add_row(
        "[dim]Algorithm[/dim]", "AES-256-GCM" if not is_streaming else "AES-256-CTR", ""
    )
    table.add_row(
        "[dim]Mode[/dim]", "In-memory" if not is_streaming else "Streaming", ""
    )
    table.add_row("[dim]SHA-256[/dim]", f"[dim]{sha256}…[/dim]", "")

    console.print(table)
    console.print(f"\n[green]✓ File successfully encrypted → {dest}[/green]")


@app.command()
def decrypt(
    file: Path = typer.Argument(..., help=".enc file to decrypt", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file"),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Overwrite if destination exists"
    ),
):
    """🔓 Decrypt a file produced by 'cipher encrypt'."""
    if output:
        dest: Optional[Path] = output
        if dest.exists() and not overwrite:
            console.print(
                f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]"
            )
            raise typer.Exit(1)
    else:
        dest = None

    console.print(Panel(f"[bold]Decrypting[/bold] [cyan]{file}[/cyan]", expand=False))
    password = _ask_password(confirm=False)

    file_size = file.stat().st_size
    is_streaming = file_size > STREAMING_THRESHOLD

    if is_streaming:
        console.print(
            f"  [dim]Large file detected - using streaming mode ({_sizeof_fmt(file_size)})[/dim]"
        )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Processing...", total=None)

        if is_streaming:
            progress.update(task, description="Decrypting...")
            tmp_dest = file.parent / f".{secrets.token_hex(8)}_decrypt"
            original_size = _decrypt_file_streaming(file, password, tmp_dest)

            progress.update(task, description="Reading metadata...")
            with open(tmp_dest, "rb") as fin:
                data = fin.read()
                name_len = struct.unpack(">I", data[:4])[0]
                filename = data[4 : 4 + name_len].decode()
                content = data[4 + name_len :]

            tmp_dest.write_bytes(content)

            if not output:
                dest = file.parent / filename
                if dest.exists() and not overwrite:
                    console.print(
                        f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]"
                    )
                    tmp_dest.unlink()
                    raise typer.Exit(1)

            tmp_dest.rename(dest)
            actual_size = dest.stat().st_size

            if actual_size != original_size:
                console.print(
                    f"[yellow]⚠ Size mismatch: expected {original_size}, got {actual_size}[/yellow]"
                )
        else:
            progress.update(task, description="Reading...")
            blob = file.read_bytes()

            progress.update(task, description="Decrypting...")
            try:
                plaintext, original_name = _decrypt_data(blob, password)
            except ValueError as exc:
                console.print(f"\n[red]✗ Failed: {exc}[/red]")
                raise typer.Exit(1)

            if not output:
                dest = file.parent / original_name
                if dest.exists() and not overwrite:
                    console.print(
                        f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]"
                    )
                    raise typer.Exit(1)
            elif Path(output).suffix != Path(original_name).suffix:
                console.print(
                    f"[yellow]⚠ Original file was '{original_name}' — saving as '{output.name}' instead.[/yellow]"
                )

            progress.update(task, description="Writing...")
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

    magic, iterations, salt, nonce, original_size = struct.unpack(
        HEADER_FMT, blob[:HEADER_SIZE]
    )

    if magic != MAGIC:
        console.print("[red]This file was not produced by file-cipher.[/red]")
        raise typer.Exit(1)

    payload_size = len(blob) - HEADER_SIZE
    sha256_full = hashlib.sha256(blob).hexdigest()
    is_streaming = original_size > STREAMING_THRESHOLD

    table = Table(title=f"📄 {file.name}", show_header=False, box=None, padding=(0, 2))
    table.add_row("[bold]Format[/bold]", magic.decode())
    table.add_row(
        "[bold]Algorithm[/bold]", "AES-256-CTR" if is_streaming else "AES-256-GCM"
    )
    table.add_row("[bold]KDF[/bold]", f"PBKDF2-SHA256 ({iterations:,} iterations)")
    table.add_row("[bold]Salt (hex)[/bold]", salt.hex())
    table.add_row("[bold]Nonce (hex)[/bold]", nonce.hex())
    table.add_row("[bold]Original size[/bold]", _sizeof_fmt(original_size))
    table.add_row("[bold]Encrypted size[/bold]", _sizeof_fmt(len(blob)))
    table.add_row("[bold]Payload size[/bold]", _sizeof_fmt(payload_size))
    table.add_row("[bold]Mode[/bold]", "Streaming" if is_streaming else "In-memory")
    table.add_row("[bold]SHA-256[/bold]", sha256_full)

    console.print(table)


import hashlib


@app.command()
def genpass(
    length: int = typer.Option(20, "-l", "--length", help="Password length (min 16)"),
    no_copy: bool = typer.Option(False, "--no-copy", help="Don't copy to clipboard"),
):
    """🎲 Generate a strong random password."""
    if length < 16:
        console.print("[red]Minimum length is 16 characters.[/red]")
        raise typer.Exit(1)

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"

    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*-_=+?"),
    ]
    password += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password)
    password = "".join(password)

    entropy = math.log2(len(alphabet) ** length)

    console.print(
        Panel(
            f"[bold green]{password}[/bold green]",
            title="Generated password",
            expand=False,
        )
    )
    console.print(
        f"  Entropy : [cyan]{entropy:.0f} bits[/cyan]  |  Length : [cyan]{length}[/cyan]  |  Alphabet : [cyan]{len(alphabet)} chars[/cyan]"
    )

    if not no_copy:
        try:
            subprocess.run(["pbcopy"], input=password.encode(), check=True)
            console.print("  [dim]✓ Copied to clipboard[/dim]")
        except FileNotFoundError, subprocess.CalledProcessError:
            try:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=password.encode(),
                    check=True,
                )
                console.print("  [dim]✓ Copied to clipboard[/dim]")
            except FileNotFoundError, subprocess.CalledProcessError:
                console.print(
                    "  [dim]Could not copy to clipboard — paste manually.[/dim]"
                )


if __name__ == "__main__":
    app()
