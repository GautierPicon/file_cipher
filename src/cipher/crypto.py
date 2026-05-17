import hashlib
import hmac
import io
import os
import queue
import struct
import secrets
import sys
import tarfile
import tempfile
import threading
from typing import Iterator

from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

MAGIC = b"CIPHER02"
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32
CHUNK_SIZE = 16 * 1024 * 1024
PADDING_BLOCK = 64 * 1024
PADDING_FLAG = 0x8000_0000

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65_536
ARGON2_PARALLELISM = 4

HEADER_FMT = f">8sIII{SALT_SIZE}s{NONCE_SIZE}sQH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

MAX_NAME_LEN = 255
MAX_CT_SIZE = CHUNK_SIZE + 512

MAX_CHUNKS = 1_000_000

FIXED_MTIME = 0

_WINDOWS = sys.platform == "win32"



class _Header:

    __slots__ = (
        "magic", "time_cost", "memory_cost", "parallelism",
        "salt", "base_nonce", "original_size", "name_len",
    )

    def __init__(
        self,
        magic: bytes,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        salt: bytes,
        base_nonce: bytes,
        original_size: int,
        name_len: int,
    ) -> None:
        self.magic = magic
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.salt = salt
        self.base_nonce = base_nonce
        self.original_size = original_size
        self.name_len = name_len

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


def _pad_size(current_size: int) -> int:
    remainder = current_size % PADDING_BLOCK
    return PADDING_BLOCK - remainder if remainder != 0 else 0


def _neutralize_metadata(path: Path) -> None:
    os.utime(path, (FIXED_MTIME, FIXED_MTIME))
    if not _WINDOWS:
        path.chmod(0o600)

def _parse_header(raw: bytes) -> _Header:
    if len(raw) < HEADER_SIZE:
        raise ValueError("File too short or corrupted.")

    magic, time_cost, memory_cost, parallelism, salt, base_nonce, original_size, name_len = (
        struct.unpack(HEADER_FMT, raw)
    )

    if not hmac.compare_digest(magic, MAGIC):
        raise ValueError("This file was not encrypted by cipher (invalid magic).")

    if name_len == 0 or name_len > MAX_NAME_LEN:
        raise ValueError(f"Invalid filename length in header ({name_len}).")

    return _Header(magic, time_cost, memory_cost, parallelism, salt, base_nonce, original_size, name_len)


def read_header(in_path: Path) -> _Header:
    with open(in_path, "rb") as fin:
        raw = fin.read(HEADER_SIZE)
    return _parse_header(raw)

def _iter_chunks(
    fin: io.BufferedReader,
    aesgcm: AESGCM,
    base_nonce: bytes,
    name_len: int,
) -> Iterator[tuple[int, bytes, bool]]:
    counter = 0

    while True:
        if counter > MAX_CHUNKS:
            raise ValueError(
                f"File exceeds maximum chunk count ({MAX_CHUNKS}). "
                "File may be corrupted or maliciously crafted."
            )

        size_buf = fin.read(4)
        if not size_buf:
            break
        if len(size_buf) < 4:
            raise ValueError("Truncated chunk size — file may be corrupted.")

        raw_size = struct.unpack(">I", size_buf)[0]
        is_padding = bool(raw_size & PADDING_FLAG)
        ct_len = raw_size & ~PADDING_FLAG

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

        if is_padding:
            break

        is_first = counter == 0
        if is_first and name_len > len(plaintext):
            raise ValueError("Corrupted header: name_len exceeds first chunk size.")

        yield counter, plaintext, is_first
        counter += 1

def encrypt_stream(
    in_path: Path,
    password: str,
    dest: Path,
    progress_task=None,
    progress=None,
) -> str:
    if in_path.is_dir():
        if not os.access(in_path, os.R_OK | os.X_OK):
            raise PermissionError(f"Cannot read directory: {in_path}")
    else:
        if not os.access(in_path, os.R_OK):
            raise PermissionError(f"Cannot read file: {in_path}")

    salt = secrets.token_bytes(SALT_SIZE)
    base_nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    is_dir = in_path.is_dir()

    if is_dir:
        filename = in_path.name + ".tar.gz"
        data_source, tar_thread, error_queue = _open_tar_source(in_path)
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

            current_size = fout.tell()
            pad_len = _pad_size(current_size)
            if pad_len > 0:
                padding = secrets.token_bytes(pad_len)
                nonce = chunk_nonce(base_nonce, counter)
                ct = aesgcm.encrypt(nonce, padding, None)
                size_prefix = struct.pack(">I", len(ct) | PADDING_FLAG)
                fout.write(size_prefix)
                fout.write(ct)
                sha256.update(size_prefix)
                sha256.update(ct)

    except Exception:
        if tmp_dest.exists():
            tmp_dest.unlink()
        raise
    finally:
        data_source.close()
        if tar_thread is not None and tar_thread.is_alive():
            tar_thread.join()

    if error_queue is not None and not error_queue.empty():
        if tmp_dest.exists():
            tmp_dest.unlink()
        raise error_queue.get_nowait()

    tmp_dest.replace(dest)
    _neutralize_metadata(dest)
    return sha256.hexdigest()


def decrypt_stream(
    in_path: Path,
    password: str,
    dest: Path,
    progress_task=None,
    progress=None,
) -> tuple[str, int]:
    with open(in_path, "rb") as fin, open(dest, "wb") as fout:
        header = _parse_header(fin.read(HEADER_SIZE))
        key = derive_key(password, header.salt, header.time_cost, header.memory_cost, header.parallelism)
        aesgcm = AESGCM(key)

        original_name: str | None = None

        for counter, plaintext, is_first in _iter_chunks(fin, aesgcm, header.base_nonce, header.name_len):
            if is_first:
                original_name = plaintext[:header.name_len].decode()
                data = plaintext[header.name_len:]
            else:
                data = plaintext

            fout.write(data)
            if progress is not None and progress_task is not None:
                progress.update(progress_task, advance=len(data))

    if original_name is None:
        raise ValueError("File contains no chunks — file may be corrupted.")

    return original_name, header.original_size


def verify_stream(in_path: Path, password: str) -> tuple[str, int]:
    with open(in_path, "rb") as fin:
        header = _parse_header(fin.read(HEADER_SIZE))
        key = derive_key(password, header.salt, header.time_cost, header.memory_cost, header.parallelism)
        aesgcm = AESGCM(key)

        original_name: str | None = None

        for counter, plaintext, is_first in _iter_chunks(fin, aesgcm, header.base_nonce, header.name_len):
            if is_first:
                original_name = plaintext[:header.name_len].decode()

    if original_name is None:
        raise ValueError("File contains no chunks — file may be corrupted.")

    return original_name, header.original_size

def _open_tar_source(path: Path) -> tuple[io.RawIOBase, threading.Thread | None, queue.Queue]:
    if _WINDOWS:
        return _open_tar_source_tempfile(path)
    return _open_tar_source_pipe(path)


def _open_tar_source_pipe(path: Path) -> tuple[io.RawIOBase, threading.Thread, queue.Queue]:
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


def _open_tar_source_tempfile(path: Path) -> tuple[io.RawIOBase, None, queue.Queue]:
    error_queue: queue.Queue = queue.Queue()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
    tmp_path = Path(tmp.name)
    tmp.close()

    try:
        with tarfile.open(tmp_path, mode="w:gz") as tar:
            tar.add(path, arcname=path.name)
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        error_queue.put(exc)
        raise

    class _SelfCleaningFile(io.RawIOBase):
        def __init__(self) -> None:
            self._fh = open(tmp_path, "rb")

        def readinto(self, b: bytearray) -> int:
            return self._fh.readinto(b)

        def read(self, size: int = -1) -> bytes:
            return self._fh.read(size)

        def readable(self) -> bool:
            return True

        def close(self) -> None:
            if not self.closed:
                try:
                    self._fh.close()
                finally:
                    tmp_path.unlink(missing_ok=True)
                    super().close()

    return _SelfCleaningFile(), None, error_queue
