import hashlib
import math
import secrets
import string
import struct
import subprocess

import typer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
from pathlib import Path, PurePath
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, FileSizeColumn, Progress, SpinnerColumn, TextColumn, TransferSpeedColumn
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
CHUNK_SIZE = 8 * 1024 * 1024

HEADER_FMT = f">8sI{SALT_SIZE}s{NONCE_SIZE}sQH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def _derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITER) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def _chunk_nonce(base_nonce: bytes, counter: int) -> bytes:
    return base_nonce[:4] + struct.pack(">Q", counter)


def _encrypt_stream(
    in_path: Path,
    password: str,
    dest: Path,
    progress_task=None,
    progress=None,
) -> str:
    salt = secrets.token_bytes(SALT_SIZE)
    base_nonce = secrets.token_bytes(NONCE_SIZE)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    filename = in_path.name
    name_bytes = filename.encode()
    original_size = in_path.stat().st_size

    header = struct.pack(
        HEADER_FMT, MAGIC, PBKDF2_ITER, salt, base_nonce, original_size, len(name_bytes)
    )

    sha256 = hashlib.sha256()
    sha256.update(header)

    with open(in_path, "rb") as fin, open(dest, "wb") as fout:
        fout.write(header)

        first_data = fin.read(CHUNK_SIZE)
        payload = name_bytes + first_data
        nonce = _chunk_nonce(base_nonce, 0)
        ct = aesgcm.encrypt(nonce, payload, None)
        size_prefix = struct.pack(">I", len(ct))
        fout.write(size_prefix)
        fout.write(ct)
        sha256.update(size_prefix)
        sha256.update(ct)
        if progress is not None and progress_task is not None:
            progress.update(progress_task, advance=len(first_data))

        counter = 1
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            nonce = _chunk_nonce(base_nonce, counter)
            ct = aesgcm.encrypt(nonce, chunk, None)
            size_prefix = struct.pack(">I", len(ct))
            fout.write(size_prefix)
            fout.write(ct)
            sha256.update(size_prefix)
            sha256.update(ct)
            counter += 1
            if progress is not None and progress_task is not None:
                progress.update(progress_task, advance=len(chunk))

    return sha256.hexdigest()


def _decrypt_stream(
    in_path: Path,
    password: str,
    dest: Path,
    progress_task=None,
    progress=None,
) -> tuple[str, int]:
    with open(in_path, "rb") as fin, open(dest, "wb") as fout:
        raw_header = fin.read(HEADER_SIZE)
        if len(raw_header) < HEADER_SIZE:
            raise ValueError("File too short or corrupted.")

        magic, iterations, salt, base_nonce, original_size, name_len = struct.unpack(
            HEADER_FMT, raw_header
        )
        if magic != MAGIC:
            raise ValueError("This file was not encrypted by file-cipher (invalid magic).")

        key = _derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)

        original_name = None
        counter = 0

        while True:
            size_buf = fin.read(4)
            if not size_buf:
                break
            if len(size_buf) < 4:
                raise ValueError("Truncated chunk size — file may be corrupted.")

            ct_len = struct.unpack(">I", size_buf)[0]
            ct = fin.read(ct_len)
            if len(ct) < ct_len:
                raise ValueError("Truncated chunk — file may be corrupted.")

            nonce = _chunk_nonce(base_nonce, counter)
            try:
                plaintext = aesgcm.decrypt(nonce, ct, None)
            except Exception:
                raise ValueError("Wrong password or file has been tampered with.")

            if counter == 0:
                original_name = plaintext[:name_len].decode()
                data = plaintext[name_len:]
            else:
                data = plaintext

            fout.write(data)
            counter += 1
            if progress is not None and progress_task is not None:
                progress.update(progress_task, advance=len(data))

    return original_name, original_size


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
    if not any(c.isupper() for c in password):
        issues.append("no uppercase")
    if not any(c.islower() for c in password):
        issues.append("no lowercase")
    if not any(c.isdigit() for c in password):
        issues.append("no digit")
    if not any(c in "!@#$%^&*-_=+?" for c in password):
        issues.append("no special character")

    common = {"password", "admin", "123456", "qwerty", "letmein", "welcome"}
    if password.lower() in common:
        issues.append("common password")

    if issues:
        return False, f"[yellow]⚠ Weak password: {', '.join(issues)}[/yellow]"
    return True, ""


def _ask_password_with_strength_check() -> str:
    while True:
        password = _ask_password(confirm=True)
        strong, warning = _check_password_strength(password)
        if strong:
            return password
        console.print(f"  {warning}")
        answer = console.input("  [dim]Keep this password anyway? (y/n): [/dim]").strip().lower()
        if answer in ("y", "yes"):
            return password
        console.print("  [dim]Please enter a new password.[/dim]")


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
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite if destination exists"),
):
    """🔒 Encrypt a file with AES-256-GCM."""
    dest = output or file.with_suffix(".enc")

    if dest.exists() and not overwrite:
        console.print(f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]")
        raise typer.Exit(1)

    console.print(Panel(f"[bold]Encrypting[/bold] [cyan]{file}[/cyan]", expand=False))
    password = _ask_password_with_strength_check()

    file_size = file.stat().st_size

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        FileSizeColumn(),
        TransferSpeedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Encrypting…", total=file_size)
        sha256 = _encrypt_stream(file, password, dest, task, progress)

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[dim]Source[/dim]", str(file), f"[dim]{_sizeof_fmt(file_size)}[/dim]")
    table.add_row("[dim]Output[/dim]", str(dest), f"[dim]{_sizeof_fmt(dest.stat().st_size)}[/dim]")
    table.add_row("[dim]Algorithm[/dim]", "AES-256-GCM (chunked)", "")
    table.add_row("[dim]SHA-256[/dim]", f"[dim]{sha256[:16]}…[/dim]", "")
    console.print(table)
    console.print(f"\n[green]✓ File successfully encrypted → {dest}[/green]")


@app.command()
def decrypt(
    file: Path = typer.Argument(..., help=".enc file to decrypt", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite if destination exists"),
):
    """🔓 Decrypt a file produced by 'cipher encrypt'."""
    console.print(Panel(f"[bold]Decrypting[/bold] [cyan]{file}[/cyan]", expand=False))
    password = _ask_password(confirm=False)

    file_size = file.stat().st_size
    tmp_dest = file.parent / f".{secrets.token_hex(8)}.tmp"

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            FileSizeColumn(),
            TransferSpeedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Decrypting…", total=file_size)
            try:
                original_name, original_size = _decrypt_stream(
                    file, password, tmp_dest, task, progress
                )
            except ValueError as exc:
                console.print(f"\n[red]✗ Failed: {exc}[/red]")
                raise typer.Exit(1)

        if output:
            dest = output
            if PurePath(output).suffix != PurePath(original_name).suffix:
                console.print(
                    f"[yellow]⚠ Original file was '{original_name}' — saving as '{output.name}' instead.[/yellow]"
                )
        else:
            dest = file.parent / original_name

        if dest.exists() and not overwrite:
            console.print(f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]")
            raise typer.Exit(1)

        tmp_dest.rename(dest)

    finally:
        if tmp_dest.exists():
            tmp_dest.unlink()

    console.print(f"[green]✓ File successfully decrypted → {dest}[/green]")
    console.print(f"   Size: {_sizeof_fmt(dest.stat().st_size)}")


@app.command()
def info(
    file: Path = typer.Argument(..., help=".enc file to inspect", exists=True),
):
    """ℹ️  Display metadata of an encrypted file (without decrypting it)."""
    with open(file, "rb") as f:
        raw = f.read(HEADER_SIZE)

    if len(raw) < HEADER_SIZE:
        console.print("[red]File too short to be a cipher file.[/red]")
        raise typer.Exit(1)

    magic, iterations, salt, base_nonce, original_size, name_len = struct.unpack(
        HEADER_FMT, raw
    )

    if magic != MAGIC:
        console.print("[red]This file was not produced by file-cipher.[/red]")
        raise typer.Exit(1)

    enc_size = file.stat().st_size

    table = Table(title=f"📄 {file.name}", show_header=False, box=None, padding=(0, 2))
    table.add_row("[bold]Format[/bold]", magic.decode())
    table.add_row("[bold]Algorithm[/bold]", "AES-256-GCM (chunked streaming)")
    table.add_row("[bold]KDF[/bold]", f"PBKDF2-SHA256 ({iterations:,} iterations)")
    table.add_row("[bold]Salt (hex)[/bold]", salt.hex())
    table.add_row("[bold]Base nonce (hex)[/bold]", base_nonce.hex())
    table.add_row("[bold]Original size[/bold]", _sizeof_fmt(original_size))
    table.add_row("[bold]Encrypted size[/bold]", _sizeof_fmt(enc_size))
    table.add_row("[bold]Chunk size[/bold]", _sizeof_fmt(CHUNK_SIZE))
    console.print(table)


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
        Panel(f"[bold green]{password}[/bold green]", title="Generated password", expand=False)
    )
    console.print(
        f"  Entropy : [cyan]{entropy:.0f} bits[/cyan]"
        f"  |  Length : [cyan]{length}[/cyan]"
        f"  |  Alphabet : [cyan]{len(alphabet)} chars[/cyan]"
    )

    if not no_copy:
        try:
            subprocess.run(["pbcopy"], input=password.encode(), check=True)
            console.print("  [dim]✓ Copied to clipboard[/dim]")
        except (FileNotFoundError, subprocess.CalledProcessError):
            try:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=password.encode(),
                    check=True,
                )
                console.print("  [dim]✓ Copied to clipboard[/dim]")
            except (FileNotFoundError, subprocess.CalledProcessError):
                console.print("  [dim]Could not copy to clipboard — paste manually.[/dim]")


if __name__ == "__main__":
    app()
