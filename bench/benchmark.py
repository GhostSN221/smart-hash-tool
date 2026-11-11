#!/usr/bin/env python3
"""Local micro-benchmarks for the core library.

Run with: python bench/benchmark.py
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from smart_hash_cracker import (  # noqa: E402
    apply_rules,
    compute_hash,
    detect_hash_types,
    dictionary_attack,
    generate_hashes,
)

WORDLIST = ROOT / "wordlist.txt"


def measure(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", help="Write the Markdown report to this file")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown")
    args = parser.parse_args()

    detection_inputs = [
        ("a" * 32 if i % 3 == 0 else "a" * 40 if i % 3 == 1 else "a" * 64)
        for i in range(20000)
    ]
    generation_inputs = [f"password-{i}" for i in range(20000)]

    _, detection_time = measure(
        lambda: [detect_hash_types(value) for value in detection_inputs]
    )
    _, generation_time = measure(
        lambda: [generate_hashes(value) for value in generation_inputs]
    )

    # Target is not in wordlist.txt and should not be produced by the rules.
    target = compute_hash(f"not-in-wordlist-{os.urandom(8).hex()}".encode(), "SHA1")
    _, crack_time = measure(
        lambda: dictionary_attack(target, ["SHA1", "RIPEMD160"], str(WORDLIST), json_mode=True)
    )
    _, crack_rules_time = measure(
        lambda: dictionary_attack(
            target, ["SHA1", "RIPEMD160"], str(WORDLIST), json_mode=True, use_rules=True
        )
    )

    words = sum(1 for line in WORDLIST.read_text().splitlines() if line.strip())
    rule_variants = len(apply_rules("test"))
    candidates = words * rule_variants

    results = {
        "environment": {
            "cpu_count": os.cpu_count(),
            "python": sys.version.split()[0],
            "wordlist_words": words,
            "rule_variants_per_word": rule_variants,
        },
        "detection": {
            "inputs": len(detection_inputs),
            "seconds": round(detection_time, 4),
            "inputs_per_second": round(len(detection_inputs) / detection_time),
        },
        "generation": {
            "plaintexts": len(generation_inputs),
            "hashes_per_plaintext": 12,
            "seconds": round(generation_time, 4),
            "hashes_per_second": round(len(generation_inputs) * 12 / generation_time),
        },
        "crack_no_rules": {
            "words": words,
            "seconds": round(crack_time, 4),
            "words_per_second": round(words / crack_time),
        },
        "crack_with_rules": {
            "words": words,
            "candidates": candidates,
            "seconds": round(crack_rules_time, 4),
            "candidates_per_second": round(candidates / crack_rules_time),
        },
    }

    if args.json:
        print(json.dumps(results, indent=2))
        return

    lines = [
        "# Benchmarks",
        "",
        "Local measurements, not a production capacity claim.",
        "",
        "| Test | Result |",
        "|---|---:|",
        f"| Detection | {results['detection']['inputs_per_second']:,} inputs/s |",
        f"| Generation | {results['generation']['hashes_per_second']:,} hashes/s |",
        f"| Dictionary crack (no rules) | {results['crack_no_rules']['words_per_second']:,} words/s |",
        f"| Dictionary crack (rules) | {results['crack_with_rules']['candidates_per_second']:,} candidates/s |",
        "",
        "```text",
        f"CPU threads: {results['environment']['cpu_count']}",
        f"Wordlist: {words:,} words",
        f"Rules: {rule_variants} variants/word",
        f"Detection: {results['detection']['seconds']}s for {results['detection']['inputs']:,} inputs",
        f"Generation: {results['generation']['seconds']}s for {results['generation']['plaintexts']:,} plaintexts",
        f"Crack (no rules): {results['crack_no_rules']['seconds']}s",
        f"Crack (rules): {results['crack_with_rules']['seconds']}s",
        "```",
        "",
    ]
    report = "\n".join(lines)

    if args.out:
        Path(args.out).write_text(report)
        print(f"wrote {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    main()
