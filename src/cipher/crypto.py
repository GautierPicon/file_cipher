import hashlib
import io
import struct
import secrets
import tarfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

MAGIC = b"CIPHER01"
SALT_SIZE = 32
NONCE_SIZE = 12
PBKDF2_ITER = 480_000
KEY_SIZE = 32
CHUNK_SIZE = 8 * 1024 * 1024

HEADER_FMT = f">8sI{SALT_SIZE}s{NONCE_SIZE}sQH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


# ── Key derivation ────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITER) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def chunk_nonce(base_nonce: bytes, counter: int) -> bytes:
    return base_nonce[:4] + struct.pack(">Q", counter)


# ── Encrypt ───────────────────────────────────────────────────────────────────

def encrypt_stream(
    in_path: Path,
    password: str,
    dest: Path,
    progress_task=None,
    progress=None,
) -> str:
    """Encrypt a file or directory to dest. Returns the SHA-256 hex digest."""
    salt = secrets.token_bytes(SALT_SIZE)
    base_nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    is_dir = in_path.is_dir()

    if is_dir:
        filename = in_path.name + ".tar.gz"
        raw_data = _dir_to_tar_bytes(in_path)
        original_size = len(raw_data)
        data_source = io.BytesIO(raw_data)
    else:
        filename = in_path.name
        original_size = in_path.stat().st_size
        data_source = open(in_path, "rb")

    name_bytes = filename.encode()

    header = struct.pack(
        HEADER_FMT, MAGIC, PBKDF2_ITER, salt, base_nonce, original_size, len(name_bytes)
    )

    sha256 = hashlib.sha256()
    sha256.update(header)

    try:
        with open(dest, "wb") as fout:
            fout.write(header)

            first_data = data_source.read(CHUNK_SIZE)
            payload = name_bytes + first_data
            nonce = chunk_nonce(base_nonce, 0)
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
                chunk = data_source.read(CHUNK_SIZE)
                if not chunk:
                    break
                nonce = chunk_nonce(base_nonce, counter)
                ct = aesgcm.encrypt(nonce, chunk, None)
                size_prefix = struct.pack(">I", len(ct))
                fout.write(size_prefix)
                fout.write(ct)
                sha256.update(size_prefix)
                sha256.update(ct)
                counter += 1
                if progress is not None and progress_task is not None:
                    progress.update(progress_task, advance=len(chunk))
    finally:
        if not is_dir:
            data_source.close()

    return sha256.hexdigest()


# ── Decrypt ───────────────────────────────────────────────────────────────────

def decrypt_stream(
    in_path: Path,
    password: str,
    dest: Path,
    progress_task=None,
    progress=None,
) -> tuple[str, int]:
    """Decrypt a .enc file to dest. Returns (original_filename, original_size)."""
    with open(in_path, "rb") as fin, open(dest, "wb") as fout:
        raw_header = fin.read(HEADER_SIZE)
        if len(raw_header) < HEADER_SIZE:
            raise ValueError("File too short or corrupted.")

        magic, iterations, salt, base_nonce, original_size, name_len = struct.unpack(
            HEADER_FMT, raw_header
        )
        if magic != MAGIC:
            raise ValueError("This file was not encrypted by cipher (invalid magic).")

        key = derive_key(password, salt, iterations)
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

            nonce = chunk_nonce(base_nonce, counter)
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


# ── Internal helpers ──────────────────────────────────────────────────────────

def _dir_to_tar_bytes(path: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(path, arcname=path.name)
    return buf.getvalue()