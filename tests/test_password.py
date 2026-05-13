import sys
from unittest.mock import patch, MagicMock
from cipher.password import generate_password, check_password_strength, copy_to_clipboard


def test_generated_password_length():
    assert len(generate_password()) == 32


def test_generated_password_is_strong():
    for _ in range(20):
        pwd = generate_password()
        ok, _ = check_password_strength(pwd)
        assert ok, f"Mot de passe généré trop faible : {pwd}"


def test_weak_password_too_short():
    ok, msg = check_password_strength("Ab1!")
    assert not ok
    assert "short" in msg


def test_weak_password_no_special():
    ok, msg = check_password_strength("StrongPassword1")
    assert not ok


def test_strong_password():
    ok, _ = check_password_strength("StrongPass1!")
    assert ok


class TestCopyToClipboard:
    def test_windows_uses_clip(self):
        with patch("cipher.password.sys.platform", "win32"):
            with patch("cipher.password.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                result = copy_to_clipboard("hello")
        assert result is True
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd == ["clip"]

    def test_macos_uses_pbcopy(self):
        with patch("cipher.password.sys.platform", "darwin"):
            with patch("cipher.password.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                result = copy_to_clipboard("hello")
        assert result is True
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd == ["pbcopy"]

    def test_linux_tries_xclip_first(self):
        with patch("cipher.password.sys.platform", "linux"):
            with patch("cipher.password.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                result = copy_to_clipboard("hello")
        assert result is True
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd == ["xclip", "-selection", "clipboard"]

    def test_linux_falls_back_to_xsel(self):
        with patch("cipher.password.sys.platform", "linux"):
            with patch("cipher.password.subprocess.run") as mock_run:
                mock_run.side_effect = [
                    FileNotFoundError,
                    MagicMock(returncode=0),
                ]
                result = copy_to_clipboard("hello")
        assert result is True
        second_cmd = mock_run.call_args_list[1][0][0]
        assert second_cmd == ["xsel", "--clipboard", "--input"]

    def test_linux_falls_back_to_wl_copy(self):
        with patch("cipher.password.sys.platform", "linux"):
            with patch("cipher.password.subprocess.run") as mock_run:
                mock_run.side_effect = [
                    FileNotFoundError,
                    FileNotFoundError,
                    MagicMock(returncode=0),
                ]
                result = copy_to_clipboard("hello")
        assert result is True
        third_cmd = mock_run.call_args_list[2][0][0]
        assert third_cmd == ["wl-copy"]

    def test_returns_false_when_all_commands_fail(self):
        with patch("cipher.password.sys.platform", "linux"):
            with patch("cipher.password.subprocess.run", side_effect=FileNotFoundError):
                result = copy_to_clipboard("hello")
        assert result is False

    def test_windows_returns_false_when_clip_fails(self):
        with patch("cipher.password.sys.platform", "win32"):
            with patch("cipher.password.subprocess.run", side_effect=FileNotFoundError):
                result = copy_to_clipboard("hello")
        assert result is False
