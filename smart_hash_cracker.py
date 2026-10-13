#!/usr/bin/env python3

import base64
import hashlib
import re
import argparse
import sys
import json
import os
import urllib.request
from concurrent.futures import ProcessPoolExecutor, as_completed

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


HASH_CANDIDATES = {
    8:   ["CRC32"],
    16:  ["MySQL323"],
    32:  ["MD5", "NTLM"],
    40:  ["SHA1", "RIPEMD160"],
    56:  ["SHA224"],
    64:  ["SHA256", "SHA3-256"],
    96:  ["SHA384"],
    128: ["SHA512", "SHA3-512"],
}

SUFFIXES = ["1", "12", "123", "1234", "12345", "!", "!!", "123!", "2023", "2024", "2025", "@", "#", "01", "007"]

LEET_TABLE = str.maketrans("aeiost", "@31057")


def is_hex(s):
    return bool(re.fullmatch(r'[0-9a-fA-F]+', s))


def detect_hash_types(s):
    if not is_hex(s):
        return []
    return HASH_CANDIDATES.get(len(s), [])


def compute_hash(word_bytes, hash_type):
    try:
        if hash_type == "MD5":
            return hashlib.md5(word_bytes).hexdigest()
        elif hash_type == "SHA1":
            return hashlib.sha1(word_bytes).hexdigest()
        elif hash_type == "SHA224":
            return hashlib.sha224(word_bytes).hexdigest()
        elif hash_type == "SHA256":
            return hashlib.sha256(word_bytes).hexdigest()
        elif hash_type == "SHA384":
            return hashlib.sha384(word_bytes).hexdigest()
        elif hash_type == "SHA512":
            return hashlib.sha512(word_bytes).hexdigest()
        elif hash_type == "SHA3-256":
            return hashlib.sha3_256(word_bytes).hexdigest()
        elif hash_type == "SHA3-512":
            return hashlib.sha3_512(word_bytes).hexdigest()
        elif hash_type == "RIPEMD160":
            return hashlib.new("ripemd160", word_bytes).hexdigest()
        elif hash_type == "NTLM":
            utf16 = word_bytes.decode("utf-8", errors="ignore").encode("utf-16-le")
            return hashlib.new("md4", utf16).hexdigest()
    except Exception:
        pass
    return None


def apply_rules(word):
    variants = []
    cap = word.capitalize()
    upper = word.upper()
    leet = word.translate(LEET_TABLE)

    variants.append(word)
    variants.append(cap)
    variants.append(upper)

    for suffix in SUFFIXES:
        variants.append(word + suffix)
        variants.append(cap + suffix)

    variants.append(leet)
    variants.append(word[::-1])

    seen = set()
    result = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


def _check_chunk(args):
    words, target, hash_types, use_rules = args
    for word in words:
        candidates = apply_rules(word) if use_rules else [word]
        for candidate in candidates:
            encoded = candidate.encode("utf-8")
            for ht in hash_types:
                if compute_hash(encoded, ht) == target:
                    return (candidate, ht)
    return None


def dictionary_attack(target_hash, hash_types, wordlist, json_mode=False, use_rules=False):
    target = target_hash.lower()

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        if not json_mode:
            print(f"Wordlist not found: {wordlist}")
        return None

    total = len(words)
    n_workers = os.cpu_count() or 4
    chunk_size = max(1, total // n_workers)
    chunks = [words[i:i + chunk_size] for i in range(0, total, chunk_size)]

    if not json_mode:
        print(f"\nDictionary attack — candidates: {', '.join(hash_types)}")
        print(f"Wordlist: {total:,} entries — {n_workers} workers")
        if use_rules:
            sample_count = len(apply_rules("test"))
            print(f"Rules: {total:,} words → ~{total * sample_count:,} candidates")
        print()

    pbar = None
    if HAS_TQDM and not json_mode:
        pbar = tqdm(total=total, unit="word", unit_scale=True, desc="Cracking")

    found = None
    with ProcessPoolExecutor(max_workers=n_workers) as executor:
        futures = {
            executor.submit(_check_chunk, (chunk, target, hash_types, use_rules)): len(chunk)
            for chunk in chunks
        }
        for fut in as_completed(futures):
            if pbar:
                pbar.update(futures[fut])
            result = fut.result()
            if result and not found:
                found = result

    if pbar:
        pbar.close()

    if found:
        return {"found": found[0], "hash_type": found[1]}
    return None


def hibp_lookup(sha1_hash):
    prefix = sha1_hash[:5].upper()
    suffix = sha1_hash[5:].upper()
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "smart-hash-tool"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
        for line in body.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                return int(parts[1])
        return 0
    except Exception:
        return None


def try_base64_decode(s):
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def try_hex_decode(s):
    try:
        return bytes.fromhex(s).decode("utf-8", errors="ignore")
    except Exception:
        return None


ALL_HASH_TYPES = [
    "MD5", "SHA1", "SHA224", "SHA256", "SHA384",
    "SHA512", "SHA3-256", "SHA3-512", "RIPEMD160", "NTLM",
]


def generate_hashes(plaintext):
    encoded = plaintext.encode("utf-8")
    results = {}
    for ht in ALL_HASH_TYPES:
        val = compute_hash(encoded, ht)
        if val:
            results[ht] = val
    return results


def analyze(user_input, wordlist=None, json_mode=False, use_rules=False, use_hibp=False):
    result = {
        "input": user_input,
        "type": None,
        "candidates": [],
        "decoded": None,
        "crack_result": None,
        "hibp_count": None,
    }

    hash_types = detect_hash_types(user_input)
    if hash_types:
        result["type"] = "hash"
        result["candidates"] = hash_types
        if not json_mode:
            print(f"\nHash detected — possible types: {', '.join(hash_types)}")

        if use_hibp and len(user_input) == 40:
            count = hibp_lookup(user_input)
            result["hibp_count"] = count
            if not json_mode:
                if count is None:
                    print("HIBP lookup failed (network error).")
                elif count == 0:
                    print("HIBP: not found in any known breach.")
                else:
                    print(f"HIBP: found {count:,} times in known breaches!")

        if wordlist:
            crack = dictionary_attack(user_input, hash_types, wordlist, json_mode, use_rules)
            result["crack_result"] = crack
            if not json_mode:
                if crack:
                    print(f"\nCRACKED [{crack['hash_type']}] -> {crack['found']}")
                else:
                    print("\nNot found in wordlist.")
        else:
            if not json_mode:
                print("No wordlist provided — use -w to attempt cracking.")
        return result

    b64 = try_base64_decode(user_input)
    if b64:
        result["type"] = "base64"
        result["decoded"] = b64
        if not json_mode:
            print(f"\nBase64 detected\nDecoded: {b64}")
        return result

    if is_hex(user_input):
        hex_dec = try_hex_decode(user_input)
        if hex_dec:
            result["type"] = "hex"
            result["decoded"] = hex_dec
            if not json_mode:
                print(f"\nHex detected\nDecoded: {hex_dec}")
            return result

    result["type"] = "unknown"
    if not json_mode:
        print("\nUnknown or unsupported format.")
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Smart Hash Analyzer & Cracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt
  %(prog)s -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt --rules
  %(prog)s -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 --hibp
  %(prog)s -s aGVsbG8=
  %(prog)s --generate "password123"
  %(prog)s -f hashes.txt -w rockyou.txt --json
        """,
    )
    parser.add_argument("-s", "--string", help="String to analyze")
    parser.add_argument("-f", "--file", help="File with one hash per line (batch mode)")
    parser.add_argument("-w", "--wordlist", help="Wordlist for dictionary attack")
    parser.add_argument("--generate", metavar="PLAINTEXT", help="Generate hashes from plaintext")
    parser.add_argument("--rules", action="store_true", help="Apply mutation rules to wordlist entries")
    parser.add_argument("--hibp", action="store_true", help="Check SHA1 hash against HaveIBeenPwned")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not any([args.string, args.file, args.generate]):
        parser.print_help()
        sys.exit(1)

    if args.generate:
        hashes = generate_hashes(args.generate)
        if args.json:
            print(json.dumps({"plaintext": args.generate, "hashes": hashes}, indent=2))
        else:
            print(f"\nHashes for: {args.generate}\n")
            for name, val in hashes.items():
                print(f"  {name:<12} {val}")
        return

    if args.file:
        try:
            with open(args.file) as f:
                hashes = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"File not found: {args.file}")
            sys.exit(1)

        results = [analyze(h, args.wordlist, args.json, args.rules, args.hibp) for h in hashes]

        if args.json:
            print(json.dumps(results, indent=2))
        return

    result = analyze(args.string.strip(), args.wordlist, args.json, args.rules, args.hibp)
    if args.json:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
