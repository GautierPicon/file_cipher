import secrets
import string
import subprocess

from getpass import getpass

import typer
from rich.console import Console

console = Console()


# ── Generation ────────────────────────────────────────────────────────────────

def generate_password(length: int = 32) -> str:
    """Generate a cryptographically strong random password."""
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
    """Try to copy text to the system clipboard. Returns True on success."""
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


# ── Strength check ────────────────────────────────────────────────────────────

def check_password_strength(password: str) -> tuple[bool, str]:
    """Return (is_strong, warning_message)."""
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


# ── Interactive prompts ───────────────────────────────────────────────────────

def ask_password(confirm: bool = False) -> str:
    """Prompt the user for a password, with optional confirmation."""
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
    """Prompt for a password, enforce strength, and allow the user to override."""
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