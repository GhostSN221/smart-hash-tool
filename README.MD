🔐 Smart Hash Tool
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
