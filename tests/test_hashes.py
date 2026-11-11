import hashlib

import pytest

from smart_hash_cracker import ALL_HASH_TYPES, _md4, compute_hash, generate_hashes

STANDARD_ALGORITHMS = {
    "MD5": "md5",
    "SHA1": "sha1",
    "SHA224": "sha224",
    "SHA256": "sha256",
    "SHA384": "sha384",
    "SHA512": "sha512",
    "SHA3-256": "sha3_256",
    "SHA3-512": "sha3_512",
}


@pytest.mark.parametrize("hash_type,hashlib_name", STANDARD_ALGORITHMS.items())
def test_standard_hashes_match_hashlib(hash_type, hashlib_name):
    expected = getattr(hashlib, hashlib_name)(b"password").hexdigest()
    assert compute_hash(b"password", hash_type) == expected


def test_ripemd160_matches_hashlib():
    expected = hashlib.new("ripemd160", b"password").hexdigest()
    assert compute_hash(b"password", "RIPEMD160") == expected


def test_ntlm_known_vector():
    # MD4(UTF-16LE("password"))
    assert compute_hash(b"password", "NTLM") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_crc32_known_vector():
    assert compute_hash(b"password", "CRC32") == "35c246d5"


def test_mysql323_known_vector():
    assert compute_hash(b"password", "MySQL323") == "5d2e19393cc5ef67"


@pytest.mark.parametrize("value,expected", [
    ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
    ("message digest", "d9130a8164549fe818874806e1c7014b"),
    ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
])
def test_md4_rfc_vectors(value, expected):
    assert _md4(value.encode()).hex() == expected


def test_ntlm_falls_back_when_openssl_disables_md4(monkeypatch):
    real_new = hashlib.new

    def fake_new(name, *args, **kwargs):
        if name == "md4":
            raise ValueError("unsupported hash type md4")
        return real_new(name, *args, **kwargs)

    monkeypatch.setattr("smart_hash_cracker.hashlib.new", fake_new)
    assert compute_hash(b"password", "NTLM") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_generate_hashes_covers_all_advertised_types():
    hashes = generate_hashes("password")
    assert set(hashes) == set(ALL_HASH_TYPES)
    assert len(hashes) == 12
    assert hashes["NTLM"] == "8846f7eaee8fb117ad06bdd830b7586c"
    assert hashes["CRC32"] == "35c246d5"
    assert hashes["MySQL323"] == "5d2e19393cc5ef67"


def test_unknown_hash_type_returns_none():
    assert compute_hash(b"password", "NOT-A-HASH") is None
