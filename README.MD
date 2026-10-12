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

1. **Automatically identifies** what it is — MD5 / SHA1 / SHA256 hash, Base64 encoding, Hex encoding
2. **Launches a dictionary attack** if it's a hash, using the wordlist you provide
3. **Decodes directly** if it's Base64 or Hex

```bash
python3 smart_hash_cracker.py -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt
# SHA1 detected → password found: "password"
```

> You throw an unknown string at it, it tells you what it is and tries to crack it — zero configuration, zero prior knowledge required.

---

A lightweight DevSecOps tool for:

🔎 Automatic hash detection (MD5, SHA1, SHA256)

📦 Base64 / Hex encoding detection

🚀 Local dictionary attacks

🐳 Docker-ready execution

📁 Project Structure
text
smart-hash-tool/
│
├── smart_hash_cracker.py
├── wordlist.txt
├── Dockerfile
└── README.md
⚙️ Features
✅ Automatic Detection
The script automatically identifies:

MD5 (32-character hex)

SHA1 (40-character hex)

SHA256 (64-character hex)

Base64

Hex encoded strings

🚀 Dictionary Attack
Test a hash against a local wordlist.

⚠️ Works only for:

Unsalted hashes

MD5 / SHA1 / SHA256

Does NOT support:

bcrypt

argon2

scrypt

Salted hashes

🐳 Docker Usage
🔨 Build
bash
docker build -t smart-hash-tool .
🔎 Basic Analysis
bash
docker run --rm smart-hash-tool -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
🚀 Dictionary Attack
bash
docker run --rm \
  -v $(pwd)/wordlist.txt:/app/wordlist.txt \
  smart-hash-tool \
  -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  -w wordlist.txt
💻 Local Usage (without Docker)
bash
python3 smart_hash_cracker.py -s <hash>
With wordlist:

bash
python3 smart_hash_cracker.py -s <hash> -w wordlist.txt
🔐 Security
Docker image based on python:3.11-slim

Runs as non-root user

No external dependencies

CI/CD friendly

Kubernetes Job compatible

📦 Kubernetes Job Example
yaml
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
        args: ["-s", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"]
      restartPolicy: Never
🎯 Use Cases
Internal security audits

Log dump analysis

CTF challenges

Basic pentesting

DevSecOps labs

⚠️ Disclaimer
This tool is intended for educational purposes and authorized internal audits only.

Unauthorized use is illegal.

🚀 Roadmap / Future Improvements
Multi-threading support

Flask API

Prometheus metrics

GitLab CI integration

Automatic log scanning

Kubernetes deployment automation
