import base64
import json
from types import SimpleNamespace

from credential_scanner import (
    Finding,
    dedupe,
    detect_reuse,
    exit_code,
    render_json,
    render_sarif,
    render_text,
    scan_file,
    scan_k8s,
    scan_path,
    scan_text,
    summary,
)
from smart_hash_cracker import compute_hash

FAKE_AWS = "AKIAABCDEFGHIJKLMNOP"
FAKE_GITHUB = "ghp_" + "a" * 36
MD5_PASSWORD = compute_hash(b"password", "MD5")
SHA1_PASSWORD = compute_hash(b"password", "SHA1")
SHA256_PASSWORD = compute_hash(b"password", "SHA256")


def test_scan_text_detects_plaintext_credentials_and_redacts():
    text = "\n".join([
        f"aws_key = {FAKE_AWS}",
        f"github = {FAKE_GITHUB}",
        "db_password = supersecret",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ])
    findings = scan_text(text, "leaky.txt")
    rules = {finding.rule for finding in findings}
    assert {"aws-access-key", "github-token", "generic-password", "private-key"} <= rules
    for finding in findings:
        assert FAKE_AWS not in finding.evidence
        assert FAKE_GITHUB not in finding.evidence
        assert "supersecret" not in finding.evidence


def test_scan_text_ignores_placeholders():
    findings = scan_text(
        "API_KEY = ${API_KEY:-}\npassword = changeme\nsecret = <redacted>\n",
        "config.yml",
    )
    assert findings == []


def test_scan_text_does_not_flag_code_annotations_or_calls():
    text = (
        "x_api_key: Optional[str] = Header(default=None)\n"
        "token = match.group(0)\n"
        "api_key = os.getenv('API_KEY', '')\n"
    )
    assert scan_text(text, "api.py") == []


def test_scan_text_can_ignore_known_test_hashes():
    assert scan_text(f"test = {MD5_PASSWORD}\n", "test.py") != []
    assert scan_text(
        f"test = {MD5_PASSWORD}\n",
        "test.py",
        ignore_hashes={MD5_PASSWORD},
    ) == []


def test_scan_text_detects_weak_and_strong_hashes():
    findings = scan_text(f"md5={MD5_PASSWORD}\nsha256={SHA256_PASSWORD}\n", "hashes.txt")
    by_rule = {finding.rule: finding for finding in findings}
    assert by_rule["weak-hash"].severity == "warning"
    assert by_rule["weak-hash"].hash_types == ["MD5", "NTLM"]
    assert by_rule["hash-candidate"].severity == "note"
    assert by_rule["hash-candidate"].hash_types == ["SHA256", "SHA3-256"]


def test_short_hashes_are_ignored_by_default():
    assert scan_text("crc=deadbeef\n", "x.txt") == []
    findings = scan_text("crc=deadbeef\n", "x.txt", min_hash_length=8)
    assert findings[0].rule == "weak-hash"
    assert findings[0].hash_types == ["CRC32"]


def test_scan_file_skips_binary_and_large_files(tmp_path):
    binary = tmp_path / "binary.bin"
    binary.write_bytes(b"\x00\x01\x02")
    assert scan_file(binary) == []

    large = tmp_path / "large.txt"
    large.write_text(FAKE_AWS)
    assert scan_file(large, max_bytes=4) == []


def test_scan_path_applies_excludes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text(f"key = {FAKE_AWS}\n")
    (tmp_path / "tests" / "test_app.py").write_text(f"key = {FAKE_AWS}\n")
    (tmp_path / "README.MD").write_text(f"key = {FAKE_AWS}\n")

    findings = scan_path(tmp_path, excludes=["tests", "README.MD"])
    assert findings
    assert all(finding.path.startswith("src/") for finding in findings)


def test_scan_k8s_secrets_and_configmaps():
    secret = SimpleNamespace(
        metadata=SimpleNamespace(name="db"),
        data={"password": base64.b64encode(FAKE_AWS.encode()).decode()},
    )
    config_map = SimpleNamespace(
        metadata=SimpleNamespace(name="app"),
        data={"config": "db_password = supersecret\n"},
    )

    class FakeApi:
        def list_namespaced_secret(self, namespace):
            return SimpleNamespace(items=[secret])

        def list_namespaced_config_map(self, namespace):
            return SimpleNamespace(items=[config_map])

    findings = scan_k8s("prod", api=FakeApi())
    rules = {finding.rule for finding in findings}
    assert "aws-access-key" in rules
    assert "generic-password" in rules
    assert any(finding.path == "k8s/secret/prod/db/password" for finding in findings)
    assert any(finding.path == "k8s/configmap/prod/app/config" for finding in findings)


def _hash_finding(path, line, value, hash_types):
    return Finding(
        rule="weak-hash",
        severity="warning",
        path=path,
        line=line,
        message="hash",
        evidence=value,
        hash_types=hash_types,
    )


def test_detect_reuse_flags_duplicate_hashes():
    findings = [
        _hash_finding("a.txt", 1, MD5_PASSWORD, ["MD5", "NTLM"]),
        _hash_finding("b.txt", 2, MD5_PASSWORD, ["MD5", "NTLM"]),
    ]
    extra = detect_reuse(findings)
    assert {finding.rule for finding in extra} == {"reused-hash"}


def test_detect_reuse_flags_reused_plaintext(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n")
    findings = [
        _hash_finding("a.txt", 1, MD5_PASSWORD, ["MD5", "NTLM"]),
        _hash_finding("b.txt", 2, SHA1_PASSWORD, ["SHA1", "RIPEMD160"]),
    ]
    extra = detect_reuse(findings, wordlist=str(wordlist))
    assert {finding.rule for finding in extra} == {"reused-password"}
    assert all(finding.severity == "error" for finding in extra)
    assert all("password" not in finding.message for finding in extra)


def test_dedupe_and_summary():
    finding = _hash_finding("a.txt", 1, MD5_PASSWORD, ["MD5"])
    findings = dedupe([finding, finding])
    assert len(findings) == 1
    assert summary(findings) == {
        "total": 1,
        "error": 0,
        "warning": 1,
        "note": 0,
        "by_rule": {"weak-hash": 1},
    }


def test_render_json_and_sarif():
    finding = _hash_finding("src/a.py", 3, MD5_PASSWORD, ["MD5", "NTLM"])
    payload = json.loads(render_json([finding]))
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["rule"] == "weak-hash"

    sarif = json.loads(render_sarif([finding]))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "weak-hash"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_render_text_empty():
    assert "No credential hygiene findings" in render_text([])


def test_exit_code():
    error = Finding("x", "error", "a", 1, "m", "e")
    warning = Finding("x", "warning", "a", 1, "m", "e")
    note = Finding("x", "note", "a", 1, "m", "e")
    assert exit_code([error], "error") == 2
    assert exit_code([warning], "error") == 0
    assert exit_code([warning], "warning") == 2
    assert exit_code([note], "warning") == 0
    assert exit_code([error], "none") == 0
