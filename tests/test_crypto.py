import pytest
from pathlib import Path
from cipher.crypto import encrypt_stream, decrypt_stream, derive_key, chunk_nonce

# ── Clé et nonce ──────────────────────────────────────────────────────────────

def test_derive_key_is_deterministic():
    salt = b"a" * 32
    k1 = derive_key("password", salt)
    k2 = derive_key("password", salt)
    assert k1 == k2

def test_derive_key_differs_with_different_salt():
    k1 = derive_key("password", b"a" * 32)
    k2 = derive_key("password", b"b" * 32)
    assert k1 != k2

def test_chunk_nonce_length():
    base = b"\x00" * 12
    assert len(chunk_nonce(base, 0)) == 12

def test_chunk_nonce_counter_changes_nonce():
    base = b"\x00" * 12
    assert chunk_nonce(base, 0) != chunk_nonce(base, 1)

# ── Encrypt / Decrypt round-trip ──────────────────────────────────────────────

def test_roundtrip_file(tmp_path):
    src = tmp_path / "hello.txt"
    src.write_bytes(b"Hello, cipher!")
    enc = tmp_path / "hello.enc"
    dec = tmp_path / "hello_dec.txt"

    encrypt_stream(src, "StrongPass1!", enc)
    name, _ = decrypt_stream(enc, "StrongPass1!", dec)

    assert name == "hello.txt"
    assert dec.read_bytes() == b"Hello, cipher!"

def test_roundtrip_empty_file(tmp_path):
    src = tmp_path / "empty.txt"
    src.write_bytes(b"")
    enc = tmp_path / "empty.enc"
    dec = tmp_path / "empty_dec.txt"

    encrypt_stream(src, "StrongPass1!", enc)
    name, _ = decrypt_stream(enc, "StrongPass1!", dec)

    assert dec.read_bytes() == b""

def test_roundtrip_binary_file(tmp_path):
    data = bytes(range(256)) * 1000
    src = tmp_path / "binary.bin"
    src.write_bytes(data)
    enc = tmp_path / "binary.enc"
    dec = tmp_path / "binary_dec.bin"

    encrypt_stream(src, "StrongPass1!", enc)
    decrypt_stream(enc, "StrongPass1!", dec)

    assert dec.read_bytes() == data

# ── Mauvais mot de passe ───────────────────────────────────────────────────────

def test_wrong_password_raises(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"sensitive data")
    enc = tmp_path / "secret.enc"
    dec = tmp_path / "secret_dec.txt"

    encrypt_stream(src, "CorrectPass1!", enc)

    with pytest.raises(ValueError, match="Wrong password"):
        decrypt_stream(enc, "WrongPass1!", dec)

# ── Intégrité ─────────────────────────────────────────────────────────────────

def test_tampered_file_raises(tmp_path):
    src = tmp_path / "data.txt"
    src.write_bytes(b"important data")
    enc = tmp_path / "data.enc"
    dec = tmp_path / "data_dec.txt"

    encrypt_stream(src, "StrongPass1!", enc)

    # Flip quelques octets au milieu du fichier
    raw = bytearray(enc.read_bytes())
    mid = len(raw) // 2
    raw[mid] ^= 0xFF
    enc.write_bytes(bytes(raw))

    with pytest.raises(ValueError):
        decrypt_stream(enc, "StrongPass1!", dec)

def test_truncated_file_raises(tmp_path):
    src = tmp_path / "data.txt"
    src.write_bytes(b"important data")
    enc = tmp_path / "data.enc"
    dec = tmp_path / "data_dec.txt"

    encrypt_stream(src, "StrongPass1!", enc)
    enc.write_bytes(enc.read_bytes()[:30])  # tronqué

    with pytest.raises(ValueError):
        decrypt_stream(enc, "StrongPass1!", dec)

# ── Dossier ───────────────────────────────────────────────────────────────────

def test_roundtrip_directory(tmp_path):
    folder = tmp_path / "my_folder"
    folder.mkdir()
    (folder / "a.txt").write_bytes(b"file A")
    (folder / "b.txt").write_bytes(b"file B")
    enc = tmp_path / "my_folder.enc"
    out_dir = tmp_path / "restored"
    out_dir.mkdir()

    encrypt_stream(folder, "StrongPass1!", enc)
    name, _ = decrypt_stream(enc, "StrongPass1!", out_dir / "my_folder.tar.gz")

    assert name == "my_folder.tar.gz"