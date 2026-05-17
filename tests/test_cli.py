import pytest
from pathlib import Path
from unittest.mock import patch
from typer.testing import CliRunner

from cipher.cli import app

runner = CliRunner()

PASSWORD = "StrongPass1!"

PATCH_STRENGTH = "cipher.cli.ask_password_with_strength_check"
PATCH_ASK      = "cipher.cli.ask_password"
PATCH_GENPASS  = "cipher.cli.generate_password"
PATCH_COPY     = "cipher.cli.copy_to_clipboard"
PATCH_SCHED    = "cipher.cli.schedule_clipboard_clear"


def _encrypt(tmp_path: Path, *extra_args, files=None, password=PASSWORD):
    if files is None:
        raise ValueError("provide at least one file path")
    paths = [str(f) for f in files]
    args = list(extra_args)
    if "--overwrite" in args and "--yes" not in args and "-y" not in args:
        args.append("--yes")
    with patch(PATCH_STRENGTH, return_value=password):
        return runner.invoke(app, ["encrypt", *paths, *args])


def _decrypt(enc: Path, *extra_args, password=PASSWORD):
    args = list(extra_args)
    if "--overwrite" in args and "--yes" not in args and "-y" not in args:
        args.append("--yes")
    with patch(PATCH_ASK, return_value=password):
        return runner.invoke(app, ["decrypt", str(enc), *args])


def _verify(enc: Path, password=PASSWORD):
    with patch(PATCH_ASK, return_value=password):
        return runner.invoke(app, ["verify", str(enc)])


class TestEncryptSingleFile:
    def test_creates_enc_file(self, tmp_path):
        src = tmp_path / "hello.txt"
        src.write_bytes(b"Hello!")
        result = _encrypt(tmp_path, files=[src])
        assert result.exit_code == 0
        assert (tmp_path / "hello.enc").exists()

    def test_output_flag(self, tmp_path):
        src = tmp_path / "hello.txt"
        src.write_bytes(b"data")
        out = tmp_path / "custom.enc"
        result = _encrypt(tmp_path, "-o", str(out), files=[src])
        assert result.exit_code == 0
        assert out.exists()

    def test_no_overwrite_by_default(self, tmp_path):
        src = tmp_path / "hello.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        result = _encrypt(tmp_path, files=[src])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_overwrite_flag(self, tmp_path):
        src = tmp_path / "hello.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        result = _encrypt(tmp_path, "--overwrite", files=[src])
        assert result.exit_code == 0

    def test_roundtrip(self, tmp_path):
        src = tmp_path / "secret.txt"
        src.write_bytes(b"top secret")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "secret.enc"
        src.unlink()
        result = _decrypt(enc)
        assert result.exit_code == 0
        assert (tmp_path / "secret.txt").read_bytes() == b"top secret"

    def test_wrong_password_on_decrypt(self, tmp_path):
        src = tmp_path / "file.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "file.enc"
        result = _decrypt(enc, password="WrongPass1!")
        assert result.exit_code == 1
        assert "Wrong password" in result.output

    def test_genpass_encrypt(self, tmp_path):
        src = tmp_path / "file.txt"
        src.write_bytes(b"data")
        generated = "Generated1!xxxxxxxxxxxxxxxxxxxxx"
        with (
            patch(PATCH_GENPASS, return_value=generated),
            patch(PATCH_COPY, return_value=False),
            patch(PATCH_SCHED),
        ):
            result = runner.invoke(app, ["encrypt", str(src), "--genpass"])
        assert result.exit_code == 0
        assert (tmp_path / "file.enc").exists()
        assert generated in result.output


class TestEncryptMultipleFiles:
    def test_encrypts_all_files(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"AAA")
        b.write_bytes(b"BBB")

        result = _encrypt(tmp_path, files=[a, b])

        assert result.exit_code == 0
        assert (tmp_path / "a.enc").exists()
        assert (tmp_path / "b.enc").exists()

    def test_each_file_decrypts_correctly(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"AAA")
        b.write_bytes(b"BBB")
        _encrypt(tmp_path, files=[a, b])

        a.unlink()
        b.unlink()

        _decrypt(tmp_path / "a.enc")
        _decrypt(tmp_path / "b.enc")

        assert (tmp_path / "a.txt").read_bytes() == b"AAA"
        assert (tmp_path / "b.txt").read_bytes() == b"BBB"

    def test_output_flag_rejected_with_multiple_files(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"A")
        b.write_bytes(b"B")

        result = _encrypt(tmp_path, "-o", str(tmp_path / "out.enc"), files=[a, b])

        assert result.exit_code == 1
        assert "--output" in result.output or "-o" in result.output

    def test_continues_after_one_conflict(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"A")
        b.write_bytes(b"B")

        (tmp_path / "a.enc").write_bytes(b"old")

        result = _encrypt(tmp_path, files=[a, b])

        assert result.exit_code == 1
        assert (tmp_path / "b.enc").exists()

    def test_overwrite_applies_to_all(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"A")
        b.write_bytes(b"B")
        _encrypt(tmp_path, files=[a, b])

        result = _encrypt(tmp_path, "--overwrite", files=[a, b])
        assert result.exit_code == 0

    def test_includes_folder_in_batch(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_bytes(b"file data")
        folder = tmp_path / "myfolder"
        folder.mkdir()
        (folder / "nested.txt").write_bytes(b"nested")

        result = _encrypt(tmp_path, files=[f, folder])

        assert result.exit_code == 0
        assert (tmp_path / "file.enc").exists()
        assert (tmp_path / "myfolder.enc").exists()

    def test_password_asked_once_for_multiple_files(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        c = tmp_path / "c.txt"
        for p in (a, b, c):
            p.write_bytes(b"x")

        with patch(PATCH_STRENGTH, return_value=PASSWORD) as mock_pwd:
            runner.invoke(app, ["encrypt", str(a), str(b), str(c)])
            mock_pwd.assert_called_once()

    def test_three_files_all_succeed(self, tmp_path):
        files = []
        for name in ("x.txt", "y.txt", "z.txt"):
            p = tmp_path / name
            p.write_bytes(name.encode())
            files.append(p)

        result = _encrypt(tmp_path, files=files)
        assert result.exit_code == 0
        for name in ("x.enc", "y.enc", "z.enc"):
            assert (tmp_path / name).exists()

    def test_error_summary_lists_failed_files(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"A")
        b.write_bytes(b"B")
        (tmp_path / "a.enc").write_bytes(b"old")
        (tmp_path / "b.enc").write_bytes(b"old")

        result = _encrypt(tmp_path, files=[a, b])

        assert result.exit_code == 1
        assert "2 file(s) failed" in result.output


class TestDecrypt:
    def test_decrypt_with_output_flag(self, tmp_path):
        src = tmp_path / "report.txt"
        src.write_bytes(b"report content")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "report.enc"
        out = tmp_path / "restored.txt"
        result = _decrypt(enc, "-o", str(out))
        assert result.exit_code == 0
        assert out.read_bytes() == b"report content"

    def test_decrypt_no_overwrite(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "data.enc"
        result = _decrypt(enc)
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_decrypt_overwrite(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "data.enc"
        result = _decrypt(enc, "--overwrite")
        assert result.exit_code == 0

    def test_overwrite_without_yes_prompts(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "data.enc"
        with patch(PATCH_ASK, return_value=PASSWORD):
            result = runner.invoke(app, ["decrypt", str(enc), "--overwrite"], input="y\n")
        assert result.exit_code == 0

    def test_overwrite_prompt_refused(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "data.enc"
        with patch(PATCH_ASK, return_value=PASSWORD):
            result = runner.invoke(app, ["decrypt", str(enc), "--overwrite"], input="n\n")
        assert result.exit_code == 0
        assert "Cancelled" in result.output


class TestVerify:
    def test_valid_file_exits_zero(self, tmp_path):
        src = tmp_path / "doc.txt"
        src.write_bytes(b"important")
        _encrypt(tmp_path, files=[src])
        result = _verify(tmp_path / "doc.enc")
        assert result.exit_code == 0

    def test_output_contains_original_filename(self, tmp_path):
        src = tmp_path / "report.pdf"
        src.write_bytes(b"pdf content")
        _encrypt(tmp_path, files=[src])
        result = _verify(tmp_path / "report.enc")
        assert "report.pdf" in result.output

    def test_wrong_password_exits_nonzero(self, tmp_path):
        src = tmp_path / "secret.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        result = _verify(tmp_path / "secret.enc", password="WrongPass1!")
        assert result.exit_code == 1
        assert "Wrong password" in result.output

    def test_tampered_file_exits_nonzero(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "data.enc"
        raw = bytearray(enc.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        enc.write_bytes(bytes(raw))
        result = _verify(enc)
        assert result.exit_code == 1

    def test_truncated_file_exits_nonzero(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_bytes(b"data")
        _encrypt(tmp_path, files=[src])
        enc = tmp_path / "data.enc"
        enc.write_bytes(enc.read_bytes()[:30])
        result = _verify(enc)
        assert result.exit_code == 1

    def test_no_output_file_written(self, tmp_path):
        src = tmp_path / "clean.txt"
        src.write_bytes(b"clean")
        _encrypt(tmp_path, files=[src])
        before = set(tmp_path.iterdir())
        _verify(tmp_path / "clean.enc")
        after = set(tmp_path.iterdir())
        assert before == after

    def test_verify_folder_enc(self, tmp_path):
        folder = tmp_path / "myfolder"
        folder.mkdir()
        (folder / "a.txt").write_bytes(b"a")
        _encrypt(tmp_path, files=[folder])
        result = _verify(tmp_path / "myfolder.enc")
        assert result.exit_code == 0
        assert "myfolder.tar.gz" in result.output
