from smart_hash_cracker import apply_rules, compute_hash, dictionary_attack


def write_wordlist(tmp_path, words):
    path = tmp_path / "words.txt"
    path.write_text("\n".join(words) + "\n")
    return path


def test_apply_rules_contains_expected_variants():
    rules = apply_rules("password")
    assert "password" in rules
    assert "Password" in rules
    assert "PASSWORD" in rules
    assert "password123" in rules
    assert "Password123!" in rules
    assert "p@55w0rd" in rules
    assert "drowssap" in rules


def test_apply_rules_deduplicates():
    rules = apply_rules("test")
    assert len(rules) == len(set(rules))


def test_crack_sha1(tmp_path):
    path = write_wordlist(tmp_path, ["123456", "password", "qwerty"])
    target = compute_hash(b"password", "SHA1")
    assert dictionary_attack(target, ["SHA1", "RIPEMD160"], str(path), json_mode=True) == {
        "found": "password",
        "hash_type": "SHA1",
    }


def test_crack_ntlm_with_md4_fallback(tmp_path):
    path = write_wordlist(tmp_path, ["password"])
    target = compute_hash(b"password", "NTLM")
    assert dictionary_attack(target, ["MD5", "NTLM"], str(path), json_mode=True) == {
        "found": "password",
        "hash_type": "NTLM",
    }


def test_crack_crc32_and_mysql323(tmp_path):
    path = write_wordlist(tmp_path, ["password"])
    crc = compute_hash(b"password", "CRC32")
    mysql = compute_hash(b"password", "MySQL323")
    assert dictionary_attack(crc, ["CRC32"], str(path), json_mode=True)["hash_type"] == "CRC32"
    assert dictionary_attack(mysql, ["MySQL323"], str(path), json_mode=True)["hash_type"] == "MySQL323"


def test_crack_with_rules(tmp_path):
    path = write_wordlist(tmp_path, ["password"])
    target = compute_hash(b"Password123!", "SHA256")
    result = dictionary_attack(target, ["SHA256"], str(path), json_mode=True, use_rules=True)
    assert result == {"found": "Password123!", "hash_type": "SHA256"}


def test_crack_returns_none_when_not_found(tmp_path):
    path = write_wordlist(tmp_path, ["123456", "password"])
    target = compute_hash(b"definitely-not-here", "SHA1")
    assert dictionary_attack(target, ["SHA1"], str(path), json_mode=True) is None


def test_crack_missing_wordlist_returns_none(tmp_path):
    target = compute_hash(b"password", "SHA1")
    assert dictionary_attack(target, ["SHA1"], str(tmp_path / "missing.txt"), json_mode=True) is None


def test_crack_empty_wordlist_returns_none(tmp_path):
    path = write_wordlist(tmp_path, [])
    target = compute_hash(b"password", "SHA1")
    assert dictionary_attack(target, ["SHA1"], str(path), json_mode=True) is None
