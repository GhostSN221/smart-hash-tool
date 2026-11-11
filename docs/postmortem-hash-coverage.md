# Postmortem: three advertised hash types were silently uncomputable

**Status:** Resolved  
**Severity:** High for audit correctness  
**Component:** `compute_hash`, `detect_hash_types`, `generate_hashes`  
**Fix:** `smart_hash_cracker.py` (NTLM fallback, CRC32, MySQL323), `tests/test_hashes.py`  
**Last updated:** 2026-11-11

> **Evidence note:** this postmortem is reconstructed from the code, the test suite and the benchmark run. The repository has no production telemetry.

---

## Summary

The README advertised **12 hash types**. Detection returned candidates for all 12, but `compute_hash` only implemented **9** of them. The other three failed silently:

- **NTLM** called `hashlib.new("md4", ...)`. OpenSSL 3 often ships without MD4, so the call raised `ValueError`, which was swallowed by a broad `except`.
- **CRC32** was listed in `HASH_CANDIDATES` but had no implementation.
- **MySQL323** was listed in `HASH_CANDIDATES` but had no implementation.

As a result, `generate_hashes("password")` returned 9 keys instead of 12 (NTLM, CRC32 and MySQL323 missing), and a dictionary attack against an NTLM/CRC32/MySQL323 target could report “not found” even when the word was in the wordlist.

---

## Impact

- Security audits could produce false negatives: an NTLM/CRC32/MySQL323 hash in the wordlist was silently skipped.
- The hash generator omitted NTLM and the two legacy formats.
- The README’s “12 hash types” claim was only true for detection, not for cracking or generation.
- No data loss; the impact was incorrect results and false confidence.

---

## Timeline

| Phase | Event |
|---|---|
| 1. Code inspection | While adding tests, `compute_hash(b"password", "NTLM")` returned `None` on Python 3.12 / OpenSSL 3. |
| 2. Reproduction | `hashlib.new("md4", ...)` raised `ValueError: unsupported hash type md4`; `generate_hashes` had no NTLM key; CRC32/MySQL323 had no branches. |
| 3. Root cause | Detection candidates and the compute dispatch were maintained separately, and the broad `except` hid the MD4 failure. |
| 4. Fix | Added a pure-Python MD4 fallback, CRC32 (`zlib`) and MySQL323; tests with known vectors. |
| 5. Verification | 12/12 types generate; NTLM fallback test forces `hashlib.new("md4")` to fail. |

---

## Root cause

Three gaps compounded each other:

1. **Detection and computation were decoupled.** `HASH_CANDIDATES` listed CRC32/MySQL323, but `compute_hash` had no corresponding branches. Nothing asserted that every advertised type was computable.
2. **MD4 is not guaranteed by OpenSSL 3.** `hashlib.new("md4")` can fail on modern distributions. The broad `except Exception: pass` turned that into a silent `None`.
3. **No tests.** A simple known-vector test for each advertised type would have caught all three.

---

## Resolution

- Added `_md4()` — a pure-Python RFC 1320 implementation used only when `hashlib` cannot provide MD4.
- Added CRC32 via `zlib.crc32` (8 hex chars, zero-padded).
- Added MySQL323 (16 hex chars, legacy `PASSWORD()` format).
- `ALL_HASH_TYPES` now contains all 12 types; `generate_hashes` returns all 12.
- Added known-vector tests:
  - NTLM `password` = `8846f7eaee8fb117ad06bdd830b7586c`
  - CRC32 `password` = `35c246d5`
  - MySQL323 `password` = `5d2e19393cc5ef67`
  - MD4 RFC vectors for `""`, `"abc"`, `"message digest"`, alphabet.
- Added a fallback test that monkeypatches `hashlib.new("md4")` to raise, proving NTLM still works.
- Added a small-wordlist sequential path so tests and small audits do not pay process-pool startup cost.

### Before / after

| Metric | Before | After |
|---|---:|---:|
| Advertised hash types | 12 | 12 |
| Computable hash types | 9 | **12** |
| `generate_hashes` keys | 9 | **12** |
| Tests | 0 | **105** |
| Coverage (`smart_hash_cracker` + `api`) | 0% | **87%** |

---

## Related detection fix

A plain word such as `test` was reported as Base64 because `base64.b64decode()` accepted it and `decode(..., errors="ignore")` returned a single printable character. The Base64 decoder now:

- requires a length multiple of 4;
- decodes strict UTF-8;
- rejects empty or non-printable results.

Hex decoding is attempted before Base64. `analyze("test")` now returns `unknown`; `analyze("aGVsbG8=")` returns `base64` → `hello`; `analyze("68656c6c6f")` returns `hex` → `hello`.

---

## Security hardening added at the same time

- **Wordlist directory restriction:** the API can only read wordlists inside `WORDLIST_DIR` (defaults to the app directory). `../outside.txt` and `/etc/passwd` return HTTP 400.
- **Optional API key:** set `API_KEY` to require `X-API-Key` on data endpoints. `/health` stays open for probes.
- **Input limits:** request bodies and `/detect` inputs are capped at 4096 characters (Pydantic validation).
- **HIBP validation:** `/hibp/{hash}` requires exactly 40 hex characters.

---

## Action items

| Action | Status |
|---|---|
| Implement NTLM fallback, CRC32 and MySQL323 | Done |
| Add known-vector tests for all advertised types | Done |
| Add tests for Base64/hex false positives | Done |
| Restrict API wordlist paths and add optional API key | Done |
| Add CI (tests, Docker, API/compose smoke) | Done |
| Add benchmarks and documented numbers | Done |
| Add salted hashes (bcrypt/argon2/scrypt) | Open |
| Prometheus metrics endpoint | Open |
| Hashcat rule-file import | Open |

---

## What went well

- A single known-vector test exposed the silent NTLM failure.
- The fix kept the CLI/API interfaces unchanged.
- The security hardening is covered by tests, not just documentation.

## What went poorly

- Detection and computation were allowed to drift apart.
- A broad exception handler hid a real platform incompatibility.
- The README made a claim that no test enforced.

## Where we got lucky

- The gap was found during test development, not during a live audit where a false negative could have been reported to a client.

---

## Verification

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

pytest tests/test_hashes.py -q
python smart_hash_cracker.py --generate password --json
```

Expected: `generate` returns 12 hashes, including NTLM, CRC32 and MySQL323.

---

## References

- `smart_hash_cracker.py` — `_md4`, `_mysql323`, `compute_hash`, `ALL_HASH_TYPES`
- `tests/test_hashes.py` — known vectors and fallback test
- `tests/test_detection.py` — Base64/hex regression tests
- `tests/test_api.py` — wordlist traversal, API key, input limits
- `docs/benchmarks.md` — local performance numbers
