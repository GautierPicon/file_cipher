from cipher.password import generate_password, check_password_strength

def test_generated_password_length():
    assert len(generate_password()) == 32

def test_generated_password_is_strong():
    for _ in range(20):  # plusieurs fois car il y a de l'aléatoire
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