import pytest

import smart_hash_cracker
from smart_hash_cracker import analyze, hibp_lookup

SHA1_PASSWORD = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
SUFFIX = SHA1_PASSWORD[5:].upper()


class FakeResponse:
    def __init__(self, body):
        self.body = body.encode()

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_hibp_lookup_found(monkeypatch):
    body = f"ABCDEF:{SUFFIX}:0\n{SUFFIX}:42\n"
    monkeypatch.setattr(
        smart_hash_cracker.urllib.request,
        "urlopen",
        lambda *args, **kwargs: FakeResponse(body),
    )
    assert hibp_lookup(SHA1_PASSWORD) == 42


def test_hibp_lookup_not_found(monkeypatch):
    monkeypatch.setattr(
        smart_hash_cracker.urllib.request,
        "urlopen",
        lambda *args, **kwargs: FakeResponse("AAAA:1\nBBBB:2\n"),
    )
    assert hibp_lookup(SHA1_PASSWORD) == 0


def test_hibp_lookup_network_error(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("network down")

    monkeypatch.setattr(smart_hash_cracker.urllib.request, "urlopen", fail)
    assert hibp_lookup(SHA1_PASSWORD) is None


def test_analyze_includes_hibp_count(monkeypatch):
    monkeypatch.setattr(smart_hash_cracker, "hibp_lookup", lambda _: 42)
    result = analyze(SHA1_PASSWORD, json_mode=True, use_hibp=True)
    assert result["hibp_count"] == 42


def test_analyze_hibp_only_for_sha1_length(monkeypatch):
    monkeypatch.setattr(smart_hash_cracker, "hibp_lookup", lambda _: pytest.fail("should not be called"))
    result = analyze("5f4dcc3b5aa765d61d8327deb882cf99", json_mode=True, use_hibp=True)
    assert result["hibp_count"] is None
