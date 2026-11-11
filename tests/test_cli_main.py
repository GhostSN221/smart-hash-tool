import json
import sys

import pytest

from smart_hash_cracker import main


def run_main(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["smart_hash_cracker.py", *args])
    main()
    return capsys.readouterr().out


def test_main_generate_json(monkeypatch, capsys):
    output = run_main(monkeypatch, capsys, "--generate", "password", "--json")
    payload = json.loads(output)
    assert payload["hashes"]["NTLM"] == "8846f7eaee8fb117ad06bdd830b7586c"


def test_main_generate_human(monkeypatch, capsys):
    output = run_main(monkeypatch, capsys, "--generate", "password")
    assert "NTLM" in output
    assert "CRC32" in output
    assert "MySQL323" in output


def test_main_detect_json(monkeypatch, capsys):
    output = run_main(
        monkeypatch,
        capsys,
        "-s",
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        "--json",
    )
    payload = json.loads(output)
    assert payload["type"] == "hash"
    assert payload["candidates"] == ["SHA1", "RIPEMD160"]


def test_main_batch_json(monkeypatch, capsys, tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\naGVsbG8=\n")
    output = run_main(monkeypatch, capsys, "-f", str(path), "--json")
    payload = json.loads(output)
    assert [item["type"] for item in payload] == ["hash", "base64"]


def test_main_requires_an_action(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["smart_hash_cracker.py"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_main_missing_file(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["smart_hash_cracker.py", "-f", "/missing/hashes.txt"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
