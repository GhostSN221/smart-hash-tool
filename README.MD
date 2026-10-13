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

1. **Automatically identifies** what it is — 12 hash types, Base64, Hex
2. **Cracks in parallel** across all CPU cores with optional mutation rules
3. **Checks HIBP** — instantly knows if the hash is in 12+ billion breached records
4. **Generates hashes** from any plaintext
5. **Exposes a REST API** — integrate it in any pipeline or tool

```bash
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt --rules --hibp
# SHA1 detected
# HIBP: found 52,372,427 times in known breaches!
# CRACKED [SHA1] -> password
```

> You throw an unknown string at it, it tells you what it is and tries to crack it — zero configuration, zero prior knowledge required.

---

## Features

| Feature | Details |
|---|---|
| Hash detection | MD5, NTLM, SHA1, RIPEMD160, SHA224, SHA256, SHA3-256, SHA384, SHA512, SHA3-512, MySQL323, CRC32 |
| Encoding detection | Base64, Hex |
| Parallel cracking | Multi-process (all CPU cores), real-time progress bar |
| Rule engine | ~35 mutations per word: capitalize, l33t, suffixes, reverse — like hashcat -r |
| HIBP lookup | Privacy-preserving k-anonymity check against 12B+ breached hashes |
| Hash generation | All hash types from a plaintext in one shot |
| Batch mode | Process a file of hashes line by line |
| REST API | FastAPI with auto-generated docs at `/docs` |
| JSON output | Machine-readable output for CI/CD pipelines |

## Installation

```bash
git clone https://github.com/GhostSN221/smart-hash-tool
cd smart-hash-tool
pip install -r requirements.txt
```

## CLI Usage

### Analyze a string

```bash
# Detect only
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

# Crack with wordlist
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt

# Crack with mutation rules (~35x more candidates)
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt --rules

# Check against Have I Been Pwned
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 --hibp

# Decode Base64 or Hex
python3 smart_hash_cracker.py -s aGVsbG8=
python3 smart_hash_cracker.py -s 68656c6c6f
```

### Generate hashes from plaintext

```bash
python3 smart_hash_cracker.py --generate "password123"
```

```
Hashes for: password123

  MD5          482c811da5d5b4bc6d497ffa98491e38
  SHA1         cbfdac6008f9cab4083784cbd1874f76618d2a97
  SHA256       ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
  ...
```

### Batch mode

```bash
python3 smart_hash_cracker.py -f hashes.txt -w rockyou.txt --rules
```

### JSON output

```bash
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt --hibp --json
```

```json
{
  "input": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
  "type": "hash",
  "candidates": ["SHA1", "RIPEMD160"],
  "crack_result": { "found": "password", "hash_type": "SHA1" },
  "hibp_count": 52372427
}
```

## REST API

### Start the server

```bash
uvicorn api:app --host 0.0.0.0 --port 8000
# Docs: http://localhost:8000/docs
```

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Healthcheck |
| POST | `/analyze` | Full analysis (detect + crack + HIBP) |
| POST | `/crack` | Dictionary attack only |
| POST | `/generate` | Generate all hash types from plaintext |
| GET | `/hibp/{sha1}` | HIBP breach lookup |
| GET | `/detect/{string}` | Detect hash type only |

### Examples

```bash
# Analyze
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"string": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "hibp": true}'

# Generate hashes
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "password123"}'

# HIBP lookup
curl http://localhost:8000/hibp/5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```

## Docker

### CLI mode

```bash
docker build -t smart-hash-tool .

docker run --rm smart-hash-tool -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

docker run --rm \
  -v $(pwd)/wordlist.txt:/app/wordlist.txt \
  smart-hash-tool -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt --rules
```

### API mode

```bash
docker compose up
# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
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
├── smart_hash_cracker.py   # CLI tool & core library
├── api.py                  # FastAPI REST server
├── wordlist.txt
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Use Cases

- Internal security audits
- Log dump analysis
- CTF challenges
- Pentesting engagements
- DevSecOps pipelines
- Security awareness labs

## Limitations

- Does not support salted hashes (bcrypt, argon2, scrypt)
- Rule engine covers common patterns — not a full hashcat ruleset

## Roadmap

- [ ] Hashcat-compatible rule file import
- [ ] Prometheus metrics endpoint
- [ ] GitLab CI integration template
- [ ] Kubernetes deployment helm chart

## Disclaimer

For educational purposes and authorized security audits only. Unauthorized use is illegal.
