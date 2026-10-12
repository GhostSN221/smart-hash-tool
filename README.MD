# Smart Hash Tool

## Context

In security, passwords are never stored in plaintext — they are hashed. During audits, CTF challenges, or when analyzing a leaked database dump, you end up facing strings like:

```
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```

You don't know what it is. You don't know how to attack it.

## Problem

The usual workflow: open Google, check the length, guess the type, pick the right tool, configure hashcat or john, find a wordlist, run it. **10–15 minutes just to get started.**

## Solution

Drop the string in. The tool does the rest:

1. **Automatically identifies** what it is — 10+ hash types, Base64, Hex
2. **Launches a parallel dictionary attack** across all CPU cores
3. **Decodes directly** if it's Base64 or Hex
4. **Generates hashes** from any plaintext
5. **Processes files** — hundreds of hashes in one shot

```bash
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt
# SHA1 detected → CRACKED [SHA1] -> password
```

> You throw an unknown string at it, it tells you what it is and tries to crack it — zero configuration, zero prior knowledge required.

---

## Features

| Feature | Details |
|---|---|
| Hash detection | MD5, NTLM, SHA1, RIPEMD160, SHA224, SHA256, SHA3-256, SHA384, SHA512, SHA3-512, MySQL323, CRC32 |
| Encoding detection | Base64, Hex |
| Dictionary attack | Multi-process (all CPU cores), progress bar, real-time speed |
| Hash generation | Compute all hash types from a plaintext in one command |
| Batch mode | Process a file of hashes line by line |
| JSON output | Machine-readable output for CI/CD pipelines |

## Installation

```bash
git clone https://github.com/Mouhmedsn02/smart-hash-tool
cd smart-hash-tool
pip install -r requirements.txt
```

## Usage

### Analyze a single string

```bash
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt
python3 smart_hash_cracker.py -s aGVsbG8=
python3 smart_hash_cracker.py -s 68656c6c6f
```

### Generate hashes from plaintext

```bash
python3 smart_hash_cracker.py --generate "password123"
```

Output:
```
Hashes for: password123

  MD5          482c811da5d5b4bc6d497ffa98491e38
  SHA1         cbfdac6008f9cab4083784cbd1874f76618d2a97
  SHA256       ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
  SHA512       bed4efa1d4fdbd954bd3705d6a2a78270ec9a52e...
  ...
```

### Batch mode — process multiple hashes

```bash
python3 smart_hash_cracker.py -f hashes.txt -w rockyou.txt
```

### JSON output (for pipelines)

```bash
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt --json
```

```json
{
  "input": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
  "type": "hash",
  "candidates": ["SHA1", "RIPEMD160"],
  "decoded": null,
  "crack_result": {
    "found": "password",
    "hash_type": "SHA1"
  }
}
```

## Docker

```bash
docker build -t smart-hash-tool .

# Analyze
docker run --rm smart-hash-tool -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

# Dictionary attack
docker run --rm \
  -v $(pwd)/wordlist.txt:/app/wordlist.txt \
  smart-hash-tool \
  -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  -w wordlist.txt

# Generate
docker run --rm smart-hash-tool --generate "password123"
```

## Kubernetes Job Example

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: hash-audit
spec:
  template:
    spec:
      containers:
      - name: hash-tool
        image: smart-hash-tool:latest
        args: ["-s", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "-w", "wordlist.txt", "--json"]
      restartPolicy: Never
```

## Project Structure

```
smart-hash-tool/
├── smart_hash_cracker.py
├── wordlist.txt
├── requirements.txt
├── Dockerfile
└── README.md
```

## Use Cases

- Internal security audits
- Log dump analysis
- CTF challenges
- Pentesting engagements
- DevSecOps pipelines

## Limitations

- Does not support salted hashes (bcrypt, argon2, scrypt)
- Dictionary attack only — no brute-force or rule engine (yet)

## Roadmap

- [ ] REST API (FastAPI)
- [ ] Rule-based mutations engine (l33tspeak, common suffixes)
- [ ] Online lookup (Have I Been Pwned)
- [ ] Prometheus metrics
- [ ] GitLab CI integration
- [ ] Kubernetes deployment automation

## Disclaimer

For educational purposes and authorized security audits only. Unauthorized use is illegal.
