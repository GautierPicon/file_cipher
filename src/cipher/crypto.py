import hashlib
import hmac
import io
import os
import queue
import struct
import secrets
import tarfile
import threading

from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

MAGIC = b"CIPHER02"
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32
CHUNK_SIZE = 16 * 1024 * 1024

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65_536
ARGON2_PARALLELISM = 4

HEADER_FMT = f">8sIII{SALT_SIZE}s{NONCE_SIZE}sQH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

MAX_NAME_LEN = 255
MAX_CT_SIZE = CHUNK_SIZE + 512


def derive_key(
    password: str,
    salt: bytes,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_SIZE,
        type=Argon2Type.ID,
    )


def chunk_nonce(base_nonce: bytes, counter: int) -> bytes:
    return base_nonce[:8] + struct.pack(">I", counter)


def encrypt_stream(
    in_path: Path,
    password: str,
    dest: Path,
    progress_task=None,
    progress=None,
) -> str:
    salt = secrets.token_bytes(SALT_SIZE)
    base_nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    is_dir = in_path.is_dir()

    if is_dir:
        filename = in_path.name + ".tar.gz"
        data_source, tar_thread, error_queue = _open_tar_pipe(in_path)
        original_size = 0
    else:
        filename = in_path.name
        original_size = in_path.stat().st_size
        data_source = open(in_path, "rb")
        tar_thread = None
        error_queue = None

    name_bytes = filename.encode()
    if len(name_bytes) > MAX_NAME_LEN:
        raise ValueError(f"Filename too long ({len(name_bytes)} bytes, max {MAX_NAME_LEN}).")

    header = struct.pack(
        HEADER_FMT,
        MAGIC,
        ARGON2_TIME_COST,
        ARGON2_MEMORY_COST,
        ARGON2_PARALLELISM,
        salt,
        base_nonce,
        original_size,
        len(name_bytes),
    )

    sha256 = hashlib.sha256()
    sha256.update(header)

    tmp_dest = dest.parent / f".{secrets.token_hex(8)}.tmp"

    try:
        with open(tmp_dest, "wb") as fout:
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
    except Exception:
        if tmp_dest.exists():
            tmp_dest.unlink()
        raise
    finally:
        data_source.close()
        if tar_thread is not None:
            tar_thread.join()

    if error_queue is not None and not error_queue.empty():
        if tmp_dest.exists():
            tmp_dest.unlink()
        raise error_queue.get_nowait()

    tmp_dest.rename(dest)
    return sha256.hexdigest()


def decrypt_stream(
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

        magic, time_cost, memory_cost, parallelism, salt, base_nonce, original_size, name_len = (
            struct.unpack(HEADER_FMT, raw_header)
        )

        if not hmac.compare_digest(magic, MAGIC):
            raise ValueError("This file was not encrypted by cipher (invalid magic).")

        if name_len == 0 or name_len > MAX_NAME_LEN:
            raise ValueError(f"Invalid filename length in header ({name_len}).")

        key = derive_key(password, salt, time_cost, memory_cost, parallelism)
        aesgcm = AESGCM(key)

        original_name: str | None = None
        counter = 0

        while True:
            size_buf = fin.read(4)
            if not size_buf:
                break
            if len(size_buf) < 4:
                raise ValueError("Truncated chunk size — file may be corrupted.")

            ct_len = struct.unpack(">I", size_buf)[0]
            if ct_len > MAX_CT_SIZE:
                raise ValueError("Chunk size exceeds maximum — file may be corrupted.")

            ct = fin.read(ct_len)
            if len(ct) < ct_len:
                raise ValueError("Truncated chunk — file may be corrupted.")

            nonce = chunk_nonce(base_nonce, counter)
            try:
                plaintext = aesgcm.decrypt(nonce, ct, None)
            except Exception:
                raise ValueError("Wrong password or file has been tampered with.")

            if counter == 0:
                if name_len > len(plaintext):
                    raise ValueError("Corrupted header: name_len exceeds first chunk size.")
                original_name = plaintext[:name_len].decode()
                data = plaintext[name_len:]
            else:
                data = plaintext

            fout.write(data)
            counter += 1
            if progress is not None and progress_task is not None:
                progress.update(progress_task, advance=len(data))

    if original_name is None:
        raise ValueError("File contains no chunks — file may be corrupted.")

    return original_name, original_size


def _open_tar_pipe(path: Path) -> tuple[io.RawIOBase, threading.Thread, queue.Queue]:
    r_fd, w_fd = os.pipe()
    error_queue: queue.Queue = queue.Queue()

    def _produce() -> None:
        try:
            with os.fdopen(w_fd, "wb") as w_file:
                with tarfile.open(fileobj=w_file, mode="w:gz") as tar:
                    tar.add(path, arcname=path.name)
        except Exception as exc:
            error_queue.put(exc)

    thread = threading.Thread(target=_produce, daemon=True)
    thread.start()
    return os.fdopen(r_fd, "rb"), thread, error_queue
