import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "smart_hash_cracker.py"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def test_generate_json_includes_all_types():
    result = run_cli("--generate", "password", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert len(payload["hashes"]) == 12
    assert payload["hashes"]["NTLM"] == "8846f7eaee8fb117ad06bdd830b7586c"
    assert payload["hashes"]["CRC32"] == "35c246d5"


def test_detect_json():
    result = run_cli("-s", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["type"] == "hash"
    assert payload["candidates"] == ["SHA1", "RIPEMD160"]


def test_plain_word_is_not_reported_as_base64():
    result = run_cli("-s", "test", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["type"] == "unknown"


def test_batch_mode_json(tmp_path):
    hashes = tmp_path / "hashes.txt"
    hashes.write_text("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\naGVsbG8=\n")
    result = run_cli("-f", str(hashes), "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert len(payload) == 2
    assert payload[0]["type"] == "hash"
    assert payload[1]["type"] == "base64"


def test_no_arguments_exits_with_usage():
    result = run_cli()
    assert result.returncode == 1
    assert "usage" in result.stdout.lower() or "usage" in result.stderr.lower()
