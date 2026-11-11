import pytest

from smart_hash_cracker import (
    analyze,
    detect_hash_types,
    is_hex,
    try_base64_decode,
    try_hex_decode,
)


@pytest.mark.parametrize("length,expected", [
    (8, ["CRC32"]),
    (16, ["MySQL323"]),
    (32, ["MD5", "NTLM"]),
    (40, ["SHA1", "RIPEMD160"]),
    (56, ["SHA224"]),
    (64, ["SHA256", "SHA3-256"]),
    (96, ["SHA384"]),
    (128, ["SHA512", "SHA3-512"]),
])
def test_detect_hash_types_by_length(length, expected):
    assert detect_hash_types("a" * length) == expected


def test_detect_accepts_uppercase_hex():
    assert detect_hash_types("A" * 40) == ["SHA1", "RIPEMD160"]


@pytest.mark.parametrize("value", ["zzzz", "not-a-hash", "hello world", "", "1234567g"])
def test_detect_rejects_non_hex(value):
    assert detect_hash_types(value) == []


def test_is_hex():
    assert is_hex("deadbeef") is True
    assert is_hex("DEADBEEF") is True
    assert is_hex("dead beef") is False
    assert is_hex("") is False


def test_plain_word_is_not_base64():
    result = analyze("test", json_mode=True)
    assert result["type"] == "unknown"
    assert result["decoded"] is None


def test_base64_text_is_decoded():
    result = analyze("aGVsbG8=", json_mode=True)
    assert result["type"] == "base64"
    assert result["decoded"] == "hello"


def test_hex_text_is_decoded_before_base64():
    result = analyze("68656c6c6f", json_mode=True)
    assert result["type"] == "hex"
    assert result["decoded"] == "hello"


def test_hash_analysis_returns_candidates():
    result = analyze("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", json_mode=True)
    assert result["type"] == "hash"
    assert result["candidates"] == ["SHA1", "RIPEMD160"]
    assert result["crack_result"] is None


def test_base64_decoder_rejects_binary_and_padding_errors():
    assert try_base64_decode("test") is None
    assert try_base64_decode("!!!!") is None
    assert try_base64_decode("aGVsbG8") is None
    assert try_base64_decode("TWFu") == "Man"


def test_hex_decoder_handles_text_and_binary():
    assert try_hex_decode("68656c6c6f") == "hello"
    assert try_hex_decode("zz") is None
    # Valid hex, but the decoded bytes are not printable text.
    assert not try_hex_decode("abcdef")
