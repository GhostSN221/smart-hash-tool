#!/usr/bin/env python3
"""Cloud-native credential hygiene scanner.

Scans repositories, CI logs and Kubernetes Secrets/ConfigMaps for:
  - plaintext credentials (AWS/GitHub/Slack tokens, private keys, password literals)
  - weak password hashes (MD5, NTLM, SHA1, RIPEMD160, MySQL323, CRC32)
  - reused hashes and, with --crack, reused plaintext passwords

Outputs text, JSON or SARIF 2.1.0 for GitHub Code Scanning.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from smart_hash_cracker import analyze, detect_hash_types

WEAK_HASH_TYPES = {"MD5", "NTLM", "SHA1", "RIPEMD160", "MySQL323", "CRC32"}
DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules",
    ".claude", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    "dist", "build",
}
MAX_FILE_BYTES = 2_000_000
TOOL_VERSION = "2.1.0"


@dataclass(frozen=True)
class SecretPattern:
    rule: str
    regex: re.Pattern[str]
    severity: str
    description: str


SECRET_PATTERNS = [
    SecretPattern(
        "aws-access-key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "error",
        "AWS access key",
    ),
    SecretPattern(
        "github-token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        "error",
        "GitHub token",
    ),
    SecretPattern(
        "slack-token",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "error",
        "Slack token",
    ),
    SecretPattern(
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
        "error",
        "Private key",
    ),
    SecretPattern(
        "generic-password",
        re.compile(r"(?i)\b[\w.-]*(?:password|passwd|pwd)\b\s*[:=]\s*['\"]?([^\s'\"#]{4,})"),
        "warning",
        "Password literal",
    ),
    SecretPattern(
        "generic-secret",
        re.compile(r"(?i)\b[\w.-]*(?:secret|token|api[_-]?key)\b\s*[:=]\s*['\"]?([^\s'\"#]{8,})"),
        "warning",
        "Secret literal",
    ),
]

HASH_RE = re.compile(r"\b[0-9a-fA-F]{8,128}\b")


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str
    evidence: str
    hash_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _redact(value: str) -> str:
    value = value.strip().strip("'\"")
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def _is_placeholder(value: str) -> bool:
    value = value.strip().strip("'\"")
    if not value or value[0] in "$<{%":
        return True
    # Type annotations, function calls and dict/list literals are code, not
    # credential values. This keeps `token = match.group(0)` out of the report.
    if any(char in value for char in "[](){}<>"):
        return True
    lowered = value.lower()
    if lowered in {
        "password", "changeme", "change-me", "secret", "token",
        "example", "your_password", "your-secret", "redacted",
        "none", "true", "false", "null",
    }:
        return True
    return lowered.startswith(("your_", "your-", "example_", "match.", "self.", "os.", "path.", "optional", "header"))


def scan_text(
    text: str,
    path: str,
    min_hash_length: int = 32,
    ignore_hashes: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()
    ignored = {value.lower() for value in (ignore_hashes or set())}

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in SECRET_PATTERNS:
            for match in pattern.regex.finditer(line):
                value = match.group(1) if match.lastindex else match.group(0)
                if _is_placeholder(value):
                    continue
                key = (pattern.rule, line_number, value)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    rule=pattern.rule,
                    severity=pattern.severity,
                    path=path,
                    line=line_number,
                    message=f"{pattern.description} detected",
                    evidence=_redact(value),
                ))

        for match in HASH_RE.finditer(line):
            token = match.group(0)
            if len(token) < min_hash_length or token.lower() in ignored:
                continue
            hash_types = detect_hash_types(token)
            if not hash_types:
                continue
            weak = any(hash_type in WEAK_HASH_TYPES for hash_type in hash_types)
            rule = "weak-hash" if weak else "hash-candidate"
            severity = "warning" if weak else "note"
            key = (rule, line_number, token)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                rule=rule,
                severity=severity,
                path=path,
                line=line_number,
                message=(
                    f"{'/'.join(hash_types)} hash detected"
                    + (" (weak algorithm)" if weak else "")
                ),
                evidence=token,
                hash_types=hash_types,
            ))

    return findings


def scan_file(
    path: Path | str,
    min_hash_length: int = 32,
    display_path: str | None = None,
    max_bytes: int = MAX_FILE_BYTES,
    ignore_hashes: set[str] | None = None,
) -> list[Finding]:
    source = Path(path)
    try:
        if source.stat().st_size > max_bytes:
            return []
        data = source.read_bytes()
    except OSError:
        return []

    if b"\x00" in data:
        return []

    text = data.decode("utf-8", errors="replace")
    return scan_text(
        text,
        display_path or str(source),
        min_hash_length,
        ignore_hashes=ignore_hashes,
    )


def scan_path(
    root: Path | str,
    excludes: Iterable[str] | None = None,
    min_hash_length: int = 32,
    ignore_hashes: set[str] | None = None,
) -> list[Finding]:
    base = Path(root)
    if base.is_file():
        return scan_file(
            base,
            min_hash_length=min_hash_length,
            ignore_hashes=ignore_hashes,
        )

    if not base.exists():
        raise FileNotFoundError(f"Path not found: {base}")

    excluded = DEFAULT_EXCLUDES | set(excludes or [])
    findings: list[Finding] = []

    for file_path in sorted(base.rglob("*")):
        if not file_path.is_file() or file_path.is_symlink():
            continue
        relative = file_path.relative_to(base)
        if any(part in excluded for part in relative.parts):
            continue
        if relative.name in excluded or str(relative) in excluded:
            continue
        findings.extend(scan_file(
            file_path,
            min_hash_length=min_hash_length,
            display_path=str(relative),
            ignore_hashes=ignore_hashes,
        ))

    return findings


def scan_k8s(
    namespace: str = "default",
    api=None,
    min_hash_length: int = 32,
    ignore_hashes: set[str] | None = None,
) -> list[Finding]:
    if api is None:
        try:
            from kubernetes import client, config
        except ImportError as exc:
            raise RuntimeError(
                "Kubernetes support requires: pip install kubernetes"
            ) from exc

        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        api = client.CoreV1Api()

    findings: list[Finding] = []

    for secret in api.list_namespaced_secret(namespace).items:
        name = secret.metadata.name
        for key, encoded in (secret.data or {}).items():
            try:
                value = base64.b64decode(encoded).decode("utf-8", errors="replace")
            except Exception:
                value = str(encoded)
            findings.extend(scan_text(
                value,
                f"k8s/secret/{namespace}/{name}/{key}",
                min_hash_length,
                ignore_hashes=ignore_hashes,
            ))

    for config_map in api.list_namespaced_config_map(namespace).items:
        name = config_map.metadata.name
        for key, value in (config_map.data or {}).items():
            findings.extend(scan_text(
                value,
                f"k8s/configmap/{namespace}/{name}/{key}",
                min_hash_length,
                ignore_hashes=ignore_hashes,
            ))

    return findings


def detect_reuse(
    findings: list[Finding],
    wordlist: str | None = None,
    max_hashes: int = 20,
) -> list[Finding]:
    hash_findings = [finding for finding in findings if finding.hash_types]
    by_hash: dict[str, list[Finding]] = defaultdict(list)
    for finding in hash_findings:
        by_hash[finding.evidence].append(finding)

    extra: list[Finding] = []

    for hash_value, items in by_hash.items():
        locations = {(item.path, item.line) for item in items}
        if len(locations) >= 2:
            for item in items:
                extra.append(Finding(
                    rule="reused-hash",
                    severity="warning",
                    path=item.path,
                    line=item.line,
                    message=f"Same hash appears in {len(locations)} locations",
                    evidence=hash_value,
                    hash_types=item.hash_types,
                ))

    if not wordlist or not Path(wordlist).is_file():
        return extra

    cracked: dict[str, set[str]] = defaultdict(set)
    for hash_value in list(by_hash)[:max_hashes]:
        result = analyze(hash_value, wordlist=wordlist, json_mode=True)
        crack = result.get("crack_result")
        if crack:
            cracked[crack["found"]].add(hash_value)

    for hashes in cracked.values():
        if len(hashes) < 2:
            continue
        for hash_value in hashes:
            for item in by_hash[hash_value]:
                extra.append(Finding(
                    rule="reused-password",
                    severity="error",
                    path=item.path,
                    line=item.line,
                    message=f"Same plaintext cracked for {len(hashes)} hashes",
                    evidence=hash_value,
                    hash_types=item.hash_types,
                ))

    return extra


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, int, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule, finding.severity, finding.path, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return sorted(result, key=lambda item: (item.path, item.line, item.rule))


def summary(findings: list[Finding]) -> dict:
    counts = {"error": 0, "warning": 0, "note": 0}
    by_rule: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
    return {"total": len(findings), **counts, "by_rule": by_rule}


def render_json(findings: list[Finding]) -> str:
    return json.dumps({
        "tool": {"name": "smart-hash-tool", "version": TOOL_VERSION},
        "summary": summary(findings),
        "findings": [finding.to_dict() for finding in findings],
    }, indent=2)


def render_sarif(findings: list[Finding]) -> str:
    rules: dict[str, dict] = {}
    for finding in findings:
        rules.setdefault(finding.rule, {
            "id": finding.rule,
            "name": finding.rule,
            "shortDescription": {"text": finding.message},
            "defaultConfiguration": {"level": finding.severity},
        })

    results = [
        {
            "ruleId": finding.rule,
            "level": finding.severity,
            "message": {"text": f"{finding.message} ({finding.evidence})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": max(1, finding.line)},
                },
            }],
        }
        for finding in findings
    ]

    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "smart-hash-tool",
                    "informationUri": "https://github.com/GhostSN221/smart-hash-tool",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }, indent=2)


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No credential hygiene findings."

    lines = [
        f"{finding.path}:{finding.line}: [{finding.severity}] "
        f"{finding.rule}: {finding.message} ({finding.evidence})"
        for finding in findings
    ]
    counts = summary(findings)
    lines.append("")
    lines.append(
        f"Total: {counts['total']} "
        f"(error={counts['error']}, warning={counts['warning']}, note={counts['note']})"
    )
    return "\n".join(lines)


def exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "none":
        return 0
    if any(finding.severity == "error" for finding in findings):
        return 2
    if fail_on == "warning" and any(finding.severity == "warning" for finding in findings):
        return 2
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Credential hygiene scanner for repositories, CI logs and Kubernetes.",
    )
    parser.add_argument("--path", default=".", help="Repository or directory to scan")
    parser.add_argument("--file", help="Scan a single file (e.g. a CI log)")
    parser.add_argument("--k8s", action="store_true", help="Scan Kubernetes Secrets and ConfigMaps")
    parser.add_argument("--namespace", default="default", help="Kubernetes namespace")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--out", help="Write the report to a file")
    parser.add_argument("--config", help="JSON config file")
    parser.add_argument("--exclude", action="append", default=[], help="Additional path to exclude")
    parser.add_argument("--fail-on", choices=["none", "warning", "error"], default=None)
    parser.add_argument("--crack", action="store_true", help="Crack hashes to detect reused passwords")
    parser.add_argument("--wordlist", default=None, help="Wordlist used with --crack")
    parser.add_argument("--max-hashes", type=int, default=20, help="Maximum hashes cracked for reuse")
    parser.add_argument("--min-hash-length", type=int, default=None, help="Minimum hex length (default 32)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    config = {}
    if args.config:
        config = json.loads(Path(args.config).read_text())

    excludes = list(config.get("exclude", [])) + args.exclude
    ignore_hashes = set(config.get("ignore_hashes", []))
    fail_on = args.fail_on or config.get("fail_on", "error")
    wordlist = args.wordlist or config.get("wordlist", "wordlist.txt")
    min_hash_length = (
        args.min_hash_length
        if args.min_hash_length is not None
        else config.get("min_hash_length", 32)
    )

    if args.k8s and args.file:
        print("--k8s and --file cannot be used together", file=sys.stderr)
        return 2

    try:
        if args.k8s:
            findings = scan_k8s(
                args.namespace,
                min_hash_length=min_hash_length,
                ignore_hashes=ignore_hashes,
            )
        elif args.file:
            if not Path(args.file).is_file():
                print(f"Path not found: {args.file}", file=sys.stderr)
                return 2
            findings = scan_file(
                args.file,
                min_hash_length=min_hash_length,
                ignore_hashes=ignore_hashes,
            )
        else:
            findings = scan_path(
                args.path,
                excludes=excludes,
                min_hash_length=min_hash_length,
                ignore_hashes=ignore_hashes,
            )
    except (FileNotFoundError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.crack:
        if not Path(wordlist).is_file():
            print(f"Wordlist not found: {wordlist}", file=sys.stderr)
            return 2
        findings += detect_reuse(findings, wordlist=wordlist, max_hashes=args.max_hashes)

    findings = dedupe(findings)

    if args.format == "json":
        report = render_json(findings)
    elif args.format == "sarif":
        report = render_sarif(findings)
    else:
        report = render_text(findings)

    if args.out:
        Path(args.out).write_text(report)
        counts = summary(findings)
        print(
            f"wrote {args.out} ({counts['total']} findings: "
            f"error={counts['error']}, warning={counts['warning']}, note={counts['note']})",
            file=sys.stderr,
        )
    else:
        print(report)

    return exit_code(findings, fail_on)


if __name__ == "__main__":
    sys.exit(main())
