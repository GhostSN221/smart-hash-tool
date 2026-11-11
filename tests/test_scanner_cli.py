import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "credential_scanner.py"
FAKE_AWS = "AKIAABCDEFGHIJKLMNOP"


def run_scanner(*args):
    return subprocess.run(
        [sys.executable, str(SCANNER), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def leaky_file(tmp_path):
    path = tmp_path / "leaky.py"
    path.write_text(
        f"key = {FAKE_AWS}\n"
        "password = supersecret\n"
        "md5 = 5f4dcc3b5aa765d61d8327deb882cf99\n"
    )
    return path


def test_scan_file_json(tmp_path):
    path = leaky_file(tmp_path)
    result = run_scanner("--file", str(path), "--format", "json", "--fail-on", "none")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total"] >= 3
    assert payload["summary"]["error"] >= 1


def test_fail_on_error_returns_2(tmp_path):
    path = leaky_file(tmp_path)
    result = run_scanner("--file", str(path), "--format", "json", "--fail-on", "error")
    assert result.returncode == 2


def test_sarif_output_file(tmp_path):
    path = leaky_file(tmp_path)
    report = tmp_path / "report.sarif"
    result = run_scanner(
        "--file", str(path),
        "--format", "sarif",
        "--fail-on", "none",
        "--out", str(report),
    )
    assert result.returncode == 0
    payload = json.loads(report.read_text())
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]


def test_config_excludes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text(f"key = {FAKE_AWS}\n")
    (tmp_path / "tests" / "test_app.py").write_text(f"key = {FAKE_AWS}\n")
    config = tmp_path / "scan.json"
    config.write_text(json.dumps({"exclude": ["tests"], "fail_on": "none"}))

    result = run_scanner(
        "--path", str(tmp_path),
        "--config", str(config),
        "--format", "json",
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["findings"]
    assert all(finding["path"].startswith("src/") for finding in payload["findings"])


def test_missing_file_returns_2(tmp_path):
    result = run_scanner("--file", str(tmp_path / "missing.txt"))
    assert result.returncode == 2
    assert "Path not found" in result.stderr


def test_k8s_and_file_conflict(tmp_path):
    result = run_scanner("--k8s", "--file", str(leaky_file(tmp_path)))
    assert result.returncode == 2


def test_min_hash_length(tmp_path):
    path = tmp_path / "short.txt"
    path.write_text("crc=deadbeef\n")
    default = run_scanner("--file", str(path), "--format", "json", "--fail-on", "none")
    assert json.loads(default.stdout)["summary"]["total"] == 0

    short = run_scanner(
        "--file", str(path),
        "--format", "json",
        "--fail-on", "none",
        "--min-hash-length", "8",
    )
    payload = json.loads(short.stdout)
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["rule"] == "weak-hash"


def test_clean_file_returns_no_findings(tmp_path):
    path = tmp_path / "clean.txt"
    path.write_text("hello world\n")
    result = run_scanner("--file", str(path), "--format", "text", "--fail-on", "none")
    assert result.returncode == 0
    assert "No credential hygiene findings" in result.stdout
