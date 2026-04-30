import secrets
import tarfile

import typer
from importlib.metadata import version as get_version
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    FileSizeColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TransferSpeedColumn,
)

from cipher.crypto import encrypt_stream, decrypt_stream
from cipher.password import (
    ask_password,
    ask_password_with_strength_check,
    copy_to_clipboard,
    generate_password,
    schedule_clipboard_clear,
)

app = typer.Typer(
    name="cipher",
    help="🔐 AES-256-GCM file encryption",
    add_completion=False,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

console = Console()
APP_VERSION = get_version("cipher")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit.",
    ),
):
    if version:
        console.print(f"cipher {APP_VERSION}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()


@app.command()
def encrypt(
    file: Path = typer.Argument(..., help="File or folder to encrypt", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite if destination exists"),
    genpass: bool = typer.Option(False, "--genpass", help="Generate a strong random password"),
):
    is_dir = file.is_dir()
    label = "folder" if is_dir else "file"
    console.print(Panel(
        f"[bold]Encrypting[/bold] [cyan]{file}[/cyan] [dim]({label})[/dim]",
        expand=False,
    ))

    if genpass:
        password = generate_password()
        clipboard_ok = copy_to_clipboard(password)
        if clipboard_ok:
            schedule_clipboard_clear(delay=30)
    else:
        password = ask_password_with_strength_check()

    dest = output or (file.with_suffix(".enc") if not is_dir else Path(str(file).rstrip("/") + ".enc"))

    if dest.exists() and not overwrite:
        console.print(f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]")
        raise typer.Exit(1)

    file_size = (
        sum(f.stat().st_size for f in file.rglob("*") if f.is_file())
        if is_dir
        else file.stat().st_size
    )

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
        sha256 = encrypt_stream(file, password, dest, task, progress)

    console.print(f"[green]✓ {label.capitalize()} successfully encrypted → {dest}[/green]")
    console.print(f"[dim]SHA-256: {sha256}[/dim]")

    if genpass:
        clipboard_note = (
            "\n[dim]📋 Copied to clipboard — cleared in 30 s.[/dim]"
            if clipboard_ok
            else "\n[dim]Could not copy to clipboard.[/dim]"
        )
        console.print(
            Panel(
                f"[bold yellow]Generated password[/bold yellow]\n\n"
                f"  [bold white on dark_red] {password} [/bold white on dark_red]\n\n"
                f"[yellow]⚠  Store this password in a safe place — it cannot be recovered.[/yellow]"
                f"{clipboard_note}",
                title="🔑 Keep this safe",
                border_style="yellow",
                expand=False,
            )
        )


@app.command()
def decrypt(
    file: Path = typer.Argument(..., help=".enc file to decrypt", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file or folder"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite if destination exists"),
):
    console.print(Panel(f"[bold]Decrypting[/bold] [cyan]{file}[/cyan]", expand=False))
    password = ask_password(confirm=False)

    tmp_dest = file.parent / f".{secrets.token_hex(8)}.tmp"

    try:
        try:
            original_name, _ = decrypt_stream(file, password, tmp_dest)
        except ValueError as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)

        is_tar = original_name.endswith(".tar.gz")

        if is_tar:
            folder_name = original_name[: -len(".tar.gz")]
            dest = output or file.parent / folder_name

            if dest.exists() and not overwrite:
                console.print(
                    f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]"
                )
                raise typer.Exit(1)

            extract_root = file.parent.resolve()
            with tarfile.open(tmp_dest, "r:gz") as tar:
                for member in tar.getmembers():
                    member_path = (extract_root / member.name).resolve()
                    if not str(member_path).startswith(str(extract_root)):
                        raise ValueError(f"Unsafe path in archive: {member.name}")
                tar.extractall(path=file.parent, filter="data")

            extracted = file.parent / folder_name
            if extracted.resolve() != dest.resolve():
                extracted.rename(dest)

            console.print(f"[green]✓ Folder successfully decrypted → {dest}[/green]")

        else:
            dest = output or file.parent / original_name

            if dest.exists() and not overwrite:
                console.print(
                    f"[yellow]⚠ '{dest}' already exists. Use --overwrite to replace it.[/yellow]"
                )
                raise typer.Exit(1)

            tmp_dest.rename(dest)
            console.print(f"[green]✓ File successfully decrypted → {dest}[/green]")

    finally:
        if tmp_dest.exists():
            tmp_dest.unlink()


if __name__ == "__main__":
    app()
