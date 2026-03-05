🔐 Smart Hash Tool








Smart Hash Tool is a lightweight DevSecOps security utility designed to analyze encoded values and weak hashes quickly.

It helps security engineers detect hash types, encodings, and weak credentials during security audits, labs, or controlled environments.

🚀 Features
🔎 Automatic Detection

The tool automatically detects common hash types and encodings:

Type	Description
MD5	32 hex characters
SHA1	40 hex characters
SHA256	64 hex characters
Base64	Encoded values
Hex	Hexadecimal encoded strings
🚀 Dictionary Attack

The tool can perform local dictionary attacks against weak hashes.

Supported algorithms:

MD5

SHA1

SHA256

⚠️ Not supported:

bcrypt

argon2

scrypt

salted hashes

📁 Project Structure
smart-hash-tool/
│
├── smart_hash_cracker.py
├── wordlist.txt
├── Dockerfile
└── README.md
🐳 Docker Usage

The tool is fully containerized and runs securely inside Docker.

🔨 Build the image
docker build -t smart-hash-tool .
🔎 Analyze a hash
docker run --rm smart-hash-tool \
-s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
🚀 Run dictionary attack
docker run --rm \
-v $(pwd)/wordlist.txt:/app/wordlist.txt \
smart-hash-tool \
-s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
-w wordlist.txt
💻 Local Usage (without Docker)

Run the script directly:

python3 smart_hash_cracker.py -s <hash>

With a wordlist:

python3 smart_hash_cracker.py -s <hash> -w wordlist.txt
☁️ Kubernetes Example

The tool can also run as a security analysis job in Kubernetes.

Example:

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

Compatible with Kubernetes and Docker environments.

🔐 Security Design

The container image follows basic security best practices:

Based on python:3.11-slim

Runs as non-root user

Minimal attack surface

No external dependencies

Compatible with CI/CD pipelines

Suitable for Kubernetes Jobs

🎯 Use Cases

Smart Hash Tool can be useful for:

🔐 DevSecOps security audits

📜 Log dump analysis

🧪 DevSecOps labs

🏴 CTF challenges

🔎 Basic pentesting scenarios

☁️ Cloud security testing

⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.

Unauthorized use against systems without explicit permission may be illegal.

The author assumes no responsibility for misuse.

🛠 Possible Future Improvements

Planned improvements could include:

Multi-threaded cracking engine

REST API with Flask

Prometheus metrics

CI/CD security pipeline integration

Automated log scanning

Kubernetes security scanning

👨‍💻 Author

DevSecOps / Cloud Security enthusiast focused on:

Cloud infrastructure security

Kubernetes security

DevSecOps automation

⭐ Support the Project

If you find this project useful:

⭐ Star the repository on GitHub

Share it with your DevOps or security community

Contribute improvements

🔥 A practical project for DevOps / DevSecOps portfolios and cloud security learning.
