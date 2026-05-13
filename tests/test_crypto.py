import pytest
from pathlib import Path
from cipher.crypto import encrypt_stream, decrypt_stream, derive_key, chunk_nonce, verify_stream

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

def test_wrong_password_raises(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"sensitive data")
    enc = tmp_path / "secret.enc"
    dec = tmp_path / "secret_dec.txt"

    encrypt_stream(src, "CorrectPass1!", enc)

    with pytest.raises(ValueError, match="Wrong password"):
        decrypt_stream(enc, "WrongPass1!", dec)

def test_tampered_file_raises(tmp_path):
    src = tmp_path / "data.txt"
    src.write_bytes(b"important data")
    enc = tmp_path / "data.enc"
    dec = tmp_path / "data_dec.txt"

    encrypt_stream(src, "StrongPass1!", enc)

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
    enc.write_bytes(enc.read_bytes()[:30])

    with pytest.raises(ValueError):
        decrypt_stream(enc, "StrongPass1!", dec)

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


class TestVerifyStream:
    def test_valid_returns_original_name(self, tmp_path):
        src = tmp_path / "hello.txt"
        src.write_bytes(b"Hello!")
        enc = tmp_path / "hello.enc"
        encrypt_stream(src, "StrongPass1!", enc)
        name, _ = verify_stream(enc, "StrongPass1!")
        assert name == "hello.txt"

    def test_valid_empty_file(self, tmp_path):
        src = tmp_path / "empty.txt"
        src.write_bytes(b"")
        enc = tmp_path / "empty.enc"
        encrypt_stream(src, "StrongPass1!", enc)
        name, _ = verify_stream(enc, "StrongPass1!")
        assert name == "empty.txt"

    def test_valid_binary_file(self, tmp_path):
        src = tmp_path / "binary.bin"
        src.write_bytes(bytes(range(256)) * 100)
        enc = tmp_path / "binary.enc"
        encrypt_stream(src, "StrongPass1!", enc)
        name, _ = verify_stream(enc, "StrongPass1!")
        assert name == "binary.bin"

    def test_wrong_password_raises(self, tmp_path):
        src = tmp_path / "secret.txt"
        src.write_bytes(b"data")
        enc = tmp_path / "secret.enc"
        encrypt_stream(src, "CorrectPass1!", enc)
        with pytest.raises(ValueError, match="Wrong password"):
            verify_stream(enc, "WrongPass1!")

    def test_tampered_file_raises(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_bytes(b"important")
        enc = tmp_path / "data.enc"
        encrypt_stream(src, "StrongPass1!", enc)
        raw = bytearray(enc.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        enc.write_bytes(bytes(raw))
        with pytest.raises(ValueError):
            verify_stream(enc, "StrongPass1!")

    def test_truncated_file_raises(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_bytes(b"important")
        enc = tmp_path / "data.enc"
        encrypt_stream(src, "StrongPass1!", enc)
        enc.write_bytes(enc.read_bytes()[:30])
        with pytest.raises(ValueError):
            verify_stream(enc, "StrongPass1!")

    def test_does_not_write_any_file(self, tmp_path):
        src = tmp_path / "clean.txt"
        src.write_bytes(b"clean data")
        enc = tmp_path / "clean.enc"
        encrypt_stream(src, "StrongPass1!", enc)
        before = set(tmp_path.iterdir())
        verify_stream(enc, "StrongPass1!")
        after = set(tmp_path.iterdir())
        assert before == after

    def test_directory_enc_returns_tar_name(self, tmp_path):
        folder = tmp_path / "myfolder"
        folder.mkdir()
        (folder / "f.txt").write_bytes(b"content")
        enc = tmp_path / "myfolder.enc"
        encrypt_stream(folder, "StrongPass1!", enc)
        name, _ = verify_stream(enc, "StrongPass1!")
        assert name == "myfolder.tar.gz"

    def test_invalid_magic_raises(self, tmp_path):
        enc = tmp_path / "fake.enc"
        enc.write_bytes(b"\x00" * 200)
        with pytest.raises(ValueError, match="invalid magic"):
            verify_stream(enc, "StrongPass1!")
