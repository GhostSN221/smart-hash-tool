import pytest
from fastapi.testclient import TestClient

import api

SHA1_PASSWORD = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
VALID_HIBP_HASH = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    return TestClient(api.app)


def small_wordlist(tmp_path):
    path = tmp_path / "small.txt"
    path.write_text("123456\npassword\nqwerty\n")
    return path


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_detect_endpoint(client):
    response = client.get(f"/detect/{SHA1_PASSWORD}")
    assert response.status_code == 200
    body = response.json()
    assert body["is_hash"] is True
    assert body["hash_types"] == ["SHA1", "RIPEMD160"]


def test_detect_rejects_long_input(client):
    response = client.get("/detect/" + "a" * 4097)
    assert response.status_code == 400


def test_generate_endpoint_includes_all_types(client):
    response = client.post("/generate", json={"plaintext": "password"})
    assert response.status_code == 200
    hashes = response.json()["hashes"]
    assert len(hashes) == 12
    assert hashes["NTLM"] == "8846f7eaee8fb117ad06bdd830b7586c"
    assert hashes["CRC32"] == "35c246d5"
    assert hashes["MySQL323"] == "5d2e19393cc5ef67"


@pytest.mark.parametrize("payload", [
    {"plaintext": ""},
    {"plaintext": "x" * 4097},
])
def test_generate_rejects_invalid_input(client, payload):
    assert client.post("/generate", json=payload).status_code == 422


def test_analyze_base64_does_not_need_wordlist(client):
    response = client.post("/analyze", json={"string": "aGVsbG8="})
    assert response.status_code == 200
    assert response.json()["type"] == "base64"
    assert response.json()["decoded"] == "hello"


def test_analyze_cracks_with_allowed_wordlist(client, tmp_path, monkeypatch):
    small_wordlist(tmp_path)
    monkeypatch.setenv("WORDLIST_DIR", str(tmp_path))

    response = client.post("/analyze", json={
        "string": SHA1_PASSWORD,
        "wordlist": "small.txt",
    })
    assert response.status_code == 200
    assert response.json()["crack_result"] == {"found": "password", "hash_type": "SHA1"}


def test_crack_with_allowed_wordlist(client, tmp_path, monkeypatch):
    small_wordlist(tmp_path)
    monkeypatch.setenv("WORDLIST_DIR", str(tmp_path))

    response = client.post("/crack", json={"hash": SHA1_PASSWORD, "wordlist": "small.txt"})
    assert response.status_code == 200
    assert response.json()["crack_result"]["found"] == "password"


def test_crack_rejects_unknown_format(client):
    assert client.post("/crack", json={"hash": "not-a-hash"}).status_code == 400


def test_wordlist_path_traversal_is_rejected(client, tmp_path, monkeypatch):
    monkeypatch.setenv("WORDLIST_DIR", str(tmp_path))
    response = client.post("/crack", json={
        "hash": SHA1_PASSWORD,
        "wordlist": "../outside.txt",
    })
    assert response.status_code == 400
    assert "inside" in response.json()["detail"]


def test_absolute_wordlist_outside_dir_is_rejected(client, tmp_path, monkeypatch):
    monkeypatch.setenv("WORDLIST_DIR", str(tmp_path))
    response = client.post("/crack", json={
        "hash": SHA1_PASSWORD,
        "wordlist": "/etc/passwd",
    })
    assert response.status_code == 400


def test_missing_wordlist_returns_400(client, tmp_path, monkeypatch):
    monkeypatch.setenv("WORDLIST_DIR", str(tmp_path))
    response = client.post("/crack", json={
        "hash": SHA1_PASSWORD,
        "wordlist": "missing.txt",
    })
    assert response.status_code == 400


def test_hibp_endpoint(client, monkeypatch):
    monkeypatch.setattr(api, "hibp_lookup", lambda _: 42)
    response = client.get(f"/hibp/{VALID_HIBP_HASH}")
    assert response.status_code == 200
    assert response.json()["breached"] is True
    assert response.json()["occurrences"] == 42


def test_hibp_zero_and_unavailable(client, monkeypatch):
    monkeypatch.setattr(api, "hibp_lookup", lambda _: 0)
    assert client.get(f"/hibp/{VALID_HIBP_HASH}").json()["breached"] is False

    monkeypatch.setattr(api, "hibp_lookup", lambda _: None)
    assert client.get(f"/hibp/{VALID_HIBP_HASH}").status_code == 503


def test_hibp_rejects_invalid_hash(client):
    assert client.get("/hibp/not-a-sha1").status_code == 400


def test_api_key_protects_endpoints_but_not_health(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "secret")
    assert client.post("/generate", json={"plaintext": "password"}).status_code == 401
    assert client.get("/health").status_code == 200
    response = client.post(
        "/generate",
        json={"plaintext": "password"},
        headers={"X-API-Key": "secret"},
    )
    assert response.status_code == 200
