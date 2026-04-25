def sizeof_fmt(num: int) -> str:
    """Convert a byte count to a human-readable string (e.g. 1.4 MB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:,.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"