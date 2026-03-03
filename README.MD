# 🔐 Smart Hash Tool

Mini outil DevSecOps permettant :

* 🔎 Détection automatique de hash (MD5, SHA1, SHA256)
* 📦 Détection encodage Base64 / Hex
* 🚀 Attaque dictionnaire locale
* 🐳 Exécution via Docker

---

## 📁 Structure du projet

```
smart-hash-tool/
│
├── smart_hash_cracker.py
├── wordlist.txt
├── Dockerfile
└── README.md
```

---

## ⚙️ Fonctionnalités

### ✅ Détection automatique

Le script détecte automatiquement :

* MD5 (32 caractères hex)
* SHA1 (40 caractères hex)
* SHA256 (64 caractères hex)
* Base64
* Hex encodé

---

### 🚀 Attaque dictionnaire

Permet de tester un hash contre une wordlist locale.

⚠️ Fonctionne uniquement pour :

* Hash non salé
* MD5 / SHA1 / SHA256

Ne supporte PAS :

* bcrypt
* argon2
* scrypt
* hash salé

---

# 🐳 Utilisation avec Docker

## 🔨 Build

```bash
docker build -t smart-hash-tool .
```

---

## 🔎 Analyse simple

```bash
docker run --rm smart-hash-tool -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```

---

## 🚀 Attaque dictionnaire

```bash
docker run --rm \
  -v $(pwd)/wordlist.txt:/app/wordlist.txt \
  smart-hash-tool \
  -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  -w wordlist.txt
```

---

# 💻 Utilisation locale (sans Docker)

```bash
python3 smart_hash_cracker.py -s <hash>
```

Avec wordlist :

```bash
python3 smart_hash_cracker.py -s <hash> -w wordlist.txt
```

---

# 🔐 Sécurité

* Image Docker basée sur python:3.11-slim
* Exécution non-root
* Aucune dépendance externe
* Compatible CI/CD
* Compatible Kubernetes Job

---

# 📦 Exemple Kubernetes Job

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
        args: ["-s", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"]
      restartPolicy: Never
```

---

# 🎯 Cas d’usage

* Audit sécurité interne
* Analyse dump logs
* CTF
* Pentest basique
* LAB DevSecOps

---

# ⚠️ Disclaimer

Cet outil est destiné à un usage éducatif et à l’audit interne autorisé uniquement.

Toute utilisation non autorisée est illégale.

---

# 🚀 Évolutions possibles

* Multi-threading
* API Flask
* Metrics Prometheus
* Intégration GitLab CI
* Scan automatique logs
* Déploiement Kubernetes

---

🔥 Projet idéal pour portfolio DevSecOps / Cloud
