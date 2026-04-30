import secrets
import string
import subprocess
import threading

from getpass import getpass

import typer
from rich.console import Console

console = Console()


def generate_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*-_=+?"),
    ]
    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    pool = required + rest
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)


def copy_to_clipboard(text: str) -> bool:
    for cmd in [
        ["pbcopy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    ]:
        try:
            subprocess.run(cmd, input=text.encode(), check=True, capture_output=True)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    return False


def schedule_clipboard_clear(delay: int = 30) -> None:
    def _clear() -> None:
        copy_to_clipboard("")

    t = threading.Timer(delay, _clear)
    t.daemon = True
    t.start()


def check_password_strength(password: str) -> tuple[bool, str]:
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


def ask_password(confirm: bool = False) -> str:
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


def ask_password_with_strength_check() -> str:
    while True:
        password = ask_password(confirm=True)
        strong, warning = check_password_strength(password)
        if strong:
            return password
        console.print(f"  {warning}")
        answer = console.input(
            "  [dim]Keep this password anyway? (y/n): [/dim]"
        ).strip().lower()
        if answer in ("y", "yes"):
            return password
        console.print("  [dim]Please enter a new password.[/dim]")
