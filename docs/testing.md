# Guide de test — Smart Hash Tool

Ce guide montre comment tester chaque partie du projet **sans toucher à la
production**.

Règles de sécurité :

- utilise uniquement des **valeurs factices** dans les exemples ;
- le scanner Kubernetes est **en lecture seule** : il liste des Secrets et des
  ConfigMaps, il ne modifie rien ;
- ne lance pas de scan sur `datacloud-ntx-v2` (cluster en lecture seule) ;
- pour un test Kubernetes, utilise un **namespace de test** et un compte de
  service dédié ;
- ne commit jamais un rapport contenant des secrets réels.

---

## 0. Se placer dans le projet

```bash
cd /home/ghost/My_Github_projects/smart-hash-tool
```

Optionnel : créer un environnement Python isolé.

```bash
python3 -m venv /tmp/opencode/smart-hash-test
source /tmp/opencode/smart-hash-test/bin/activate
pip install -r requirements-dev.txt
```

---

## 1. Tests automatiques

```bash
pytest -q
```

Résultat attendu :

```text
110 passed
```

Avec la couverture :

```bash
pytest -q \
  --cov=smart_hash_cracker \
  --cov=api \
  --cov=credential_scanner \
  --cov-report=term-missing
```

Résultat attendu : environ **88 %**.

Lint :

```bash
ruff check smart_hash_cracker.py api.py credential_scanner.py tests bench
```

Résultat attendu : `All checks passed!`.

Tests Kubernetes sans cluster réel (fausse API) :

```bash
pytest -q tests/test_scanner.py
```

---

## 2. Tester le moteur de hash (CLI)

### Génération

```bash
python3 smart_hash_cracker.py --generate password --json
```

Vérifie que la sortie contient **12 formats**, dont :

- `NTLM` = `8846f7eaee8fb117ad06bdd830b7586c`
- `CRC32` = `35c246d5`
- `MySQL323` = `5d2e19393cc5ef67`

### Détection

```bash
python3 smart_hash_cracker.py \
  -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  --json
```

Résultat attendu :

```json
{
  "type": "hash",
  "candidates": ["SHA1", "RIPEMD160"]
}
```

### Crack avec wordlist

```bash
python3 smart_hash_cracker.py \
  -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  -w wordlist.txt \
  --json
```

Résultat attendu :

```json
"crack_result": {
  "found": "password",
  "hash_type": "SHA1"
}
```

### Règles de mutation

```bash
python3 smart_hash_cracker.py \
  -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  -w wordlist.txt \
  --rules \
  --json
```

### HIBP (optionnel, réseau requis)

```bash
python3 smart_hash_cracker.py \
  -s 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  --hibp
```

Si le réseau est indisponible, le résultat peut être `HIBP lookup failed`.

### Mode batch

```bash
printf '%s\n' \
  5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  aGVsbG8= > /tmp/hashes.txt

python3 smart_hash_cracker.py -f /tmp/hashes.txt --json
```

Résultat attendu : une liste de 2 résultats (`hash`, `base64`).

---

## 3. Tester l’API

Lance le serveur :

```bash
uvicorn api:app --host 127.0.0.1 --port 8000
```

Dans un autre terminal :

```bash
curl -s http://127.0.0.1:8000/health
```

Résultat attendu : `{"status":"ok"}`.

### Détection

```bash
curl -s http://127.0.0.1:8000/detect/5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```

### Génération

```bash
curl -s -X POST http://127.0.0.1:8000/generate \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"password"}' | python3 -m json.tool
```

Vérifie les 12 hashs.

### Crack

```bash
curl -s -X POST http://127.0.0.1:8000/crack \
  -H 'Content-Type: application/json' \
  -d '{"hash":"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8","wordlist":"wordlist.txt"}' \
  | python3 -m json.tool
```

### Sandbox de wordlist

```bash
curl -i -X POST http://127.0.0.1:8000/crack \
  -H 'Content-Type: application/json' \
  -d '{"hash":"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8","wordlist":"../etc/passwd"}'
```

Résultat attendu : **HTTP 400**, `Wordlist must be inside ...`.

### Clé API

Relance l’API avec une clé :

```bash
API_KEY=secret uvicorn api:app --host 127.0.0.1 --port 8001
```

Sans clé :

```bash
curl -i -X POST http://127.0.0.1:8001/generate \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"password"}'
```

Attendu : **401**.

Avec la clé :

```bash
curl -i -X POST http://127.0.0.1:8001/generate \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: secret' \
  -d '{"plaintext":"password"}'
```

Attendu : **200**.

### Validation d’entrée

```bash
curl -i -X POST http://127.0.0.1:8000/generate \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":""}'
```

Attendu : **422**.

---

## 4. Tester le scanner sur des fichiers

Crée un fichier de test avec des **fausses** valeurs :

```bash
mkdir -p /tmp/credential-test

cat > /tmp/credential-test/leaky.env <<'EOF'
AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP
DB_PASSWORD=supersecret
MD5=5f4dcc3b5aa765d61d8327deb882cf99
SHA256=5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
EOF
```

Scan :

```bash
python credential_scanner.py \
  --file /tmp/credential-test/leaky.env \
  --format text \
  --fail-on none
```

Résultat attendu : 4 findings.

```text
/tmp/credential-test/leaky.env:1: [error] aws-access-key: AWS access key detected (AKIA…MNOP)
/tmp/credential-test/leaky.env:2: [warning] generic-password: Password literal detected (supe…cret)
/tmp/credential-test/leaky.env:3: [warning] weak-hash: MD5/NTLM hash detected (weak algorithm) (...)
/tmp/credential-test/leaky.env:4: [note] hash-candidate: SHA256/SHA3-256 hash detected (...)
```

Les valeurs sont **redactées**.

### Code de sortie

```bash
python credential_scanner.py \
  --file /tmp/credential-test/leaky.env \
  --format json \
  --fail-on error

echo "exit=$?"
```

Attendu : `exit=2` (car il y a un `error`).

### JSON

```bash
python credential_scanner.py \
  --file /tmp/credential-test/leaky.env \
  --format json \
  --fail-on none \
  | python3 -m json.tool
```

### SARIF

```bash
python credential_scanner.py \
  --file /tmp/credential-test/leaky.env \
  --format sarif \
  --fail-on none \
  --out /tmp/credential-test/scan.sarif

python3 -m json.tool /tmp/credential-test/scan.sarif | head
```

Attendu : `"version": "2.1.0"` et des `results`.

### Fichier propre

```bash
echo "hello world" > /tmp/credential-test/clean.txt

python credential_scanner.py \
  --file /tmp/credential-test/clean.txt \
  --format text
```

Attendu : `No credential hygiene findings.`

### Hash réutilisé (sans crack)

```bash
mkdir -p /tmp/credential-test/reuse
HASH=5f4dcc3b5aa765d61d8327deb882cf99

printf 'md5=%s\n' "$HASH" > /tmp/credential-test/reuse/a.txt
printf 'md5=%s\n' "$HASH" > /tmp/credential-test/reuse/b.txt

python credential_scanner.py \
  --path /tmp/credential-test/reuse \
  --format text \
  --fail-on none
```

Attendu : `reused-hash`.

### Mot de passe réutilisé (avec crack)

```bash
mkdir -p /tmp/credential-test/passwords

printf 'md5=5f4dcc3b5aa765d61d8327deb882cf99\n' \
  > /tmp/credential-test/passwords/a.txt
printf 'sha1=5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n' \
  > /tmp/credential-test/passwords/b.txt

python credential_scanner.py \
  --path /tmp/credential-test/passwords \
  --crack \
  --wordlist wordlist.txt \
  --format text \
  --fail-on none
```

Attendu : `reused-password` (le mot de passe `password` est cracké pour deux
hashs différents).

### Tester le repo lui-même

```bash
make scan
```

Attendu : `No credential hygiene findings.` grâce à `.credential-scan.json`
qui exclut les tests, docs, README et wordlist, et ignore les hashs de test.

```bash
make self-scan
```

Attendu : création de `credential-scan.sarif`.

---

## 5. Tester le scanner Kubernetes

### 5.1 Sans cluster réel

```bash
pytest -q tests/test_scanner.py
```

Ces tests utilisent une **fausse API Kubernetes** : aucun cluster n’est contacté.

### 5.2 Avec un kubeconfig local

Vérifie le contexte :

```bash
kubectl config current-context
```

Vérifie les droits en lecture :

```bash
kubectl auth can-i list secrets -n <namespace>
kubectl auth can-i list configmaps -n <namespace>
```

Lance le scan :

```bash
python credential_scanner.py \
  --k8s \
  --namespace <namespace> \
  --kubeconfig ~/.kube/config \
  --context <contexte> \
  --format text
```

Ou avec le kubeconfig courant :

```bash
python credential_scanner.py --k8s --namespace <namespace> --format text
```

### 5.3 Tous les namespaces

```bash
python credential_scanner.py \
  --k8s \
  --all-namespaces \
  --kubeconfig ~/.kube/config \
  --context <contexte> \
  --format json
```

Cela nécessite un `ClusterRole` avec `get`/`list` sur `secrets` et `configmaps`.
Sans ce droit, l’API renvoie **403** et le scanner affiche une erreur.

### 5.4 Avec un Secret de test (lab uniquement)

> Uniquement dans un namespace de **lab**, jamais dans `datacloud-ntx-v2` ni en
> production. Supprime le Secret après le test.

```bash
kubectl create namespace scanner-lab
kubectl create secret generic scanner-test \
  --from-literal=db_password=supersecret \
  -n scanner-lab

python credential_scanner.py \
  --k8s \
  --namespace scanner-lab \
  --format text

kubectl delete secret scanner-test -n scanner-lab
kubectl delete namespace scanner-lab
```

Attendu : un finding `generic-password` sur
`k8s/secret/scanner-lab/scanner-test/db_password`, avec la valeur redactée.

### 5.5 Dans le cluster (Job)

Le README contient le RBAC et le Job Kubernetes complets. En résumé :

- un `ServiceAccount` dédié ;
- un `Role` en lecture seule sur `secrets` et `configmaps` ;
- un `RoleBinding` dans le namespace cible ;
- un `Job` qui lance `credential_scanner.py --k8s --namespace ...`.

Ne crée ces ressources que dans un environnement de lab, avec l’accord de
l’équipe. Le scanner ne fait que des `list`/`get`.

### 5.6 Erreurs attendues

| Erreur | Cause | Correction |
|---|---|---|
| `403 Forbidden` | pas de droit `list` | ajouter le `Role`/`ClusterRole` |
| `Invalid kube-config` | mauvais `--kubeconfig` | vérifier le chemin |
| `context ... does not exist` | mauvais `--context` | `kubectl config get-contexts` |
| `No credential hygiene findings` | namespace vide ou rien à signaler | normal |

---

## 6. Tester Docker et Compose

### Image CLI

```bash
docker build -t smart-hash-tool:local .

docker run --rm smart-hash-tool:local --generate password --json
```

### Scanner dans Docker

```bash
docker run --rm \
  --entrypoint python3 \
  -v /tmp/credential-test:/scan:ro \
  smart-hash-tool:local \
  credential_scanner.py --file /scan/leaky.env --format text --fail-on none
```

### API + scanner avec Compose

```bash
docker compose up -d --build
curl -s http://localhost:8000/health

docker compose --profile scanner run --rm scanner

docker compose down -v
```

Attendu : API healthy, puis `No credential hygiene findings` sur le repo.

### Docker + Kubernetes

```bash
docker run --rm \
  -e KUBECONFIG=/kube/config \
  -v ~/.kube/config:/kube/config:ro \
  --entrypoint python3 \
  smart-hash-tool:local \
  credential_scanner.py --k8s --namespace <namespace> --format text
```

---

## 7. Tester la CI GitHub

1. Pousse un commit ou ouvre une PR.
2. Va dans **Actions** :
   - workflow `CI` : tests 3.11/3.12, lint, Docker, API, Compose ;
   - workflow `Credential Hygiene` : self-scan + upload SARIF.
3. Va dans **Security → Code scanning** pour voir les résultats SARIF.
4. Vérifie que le self-scan du repo ne trouve rien.

---

## 8. Nettoyage

```bash
deactivate 2>/dev/null || true
docker compose down -v 2>/dev/null || true
rm -rf /tmp/credential-test /tmp/hashes.txt
```

Ne supprime jamais un PVC, un PV, un volume Cinder ou une base de données pour
nettoyer un test. Ce guide ne crée que des fichiers temporaires et, si tu le
choisis, un namespace de lab explicitement identifié.

---

## 9. Checklist rapide

| Test | Commande | Attendu |
|---|---|---|
| Tests | `pytest -q` | 110 passed |
| Lint | `ruff check ...` | All checks passed |
| Génération | `--generate password --json` | 12 hashs |
| Détection | `-s 5baa... --json` | SHA1/RIPEMD160 |
| Crack | `-s 5baa... -w wordlist.txt` | `password` |
| API health | `curl /health` | `{"status":"ok"}` |
| API sandbox | wordlist `../etc/passwd` | HTTP 400 |
| Scanner fichier | `--file leaky.env` | 4 findings |
| Scanner repo | `make scan` | aucun finding |
| SARIF | `make self-scan` | `credential-scan.sarif` |
| K8s unit | `pytest tests/test_scanner.py` | passed |
| K8s réel | `--k8s --namespace ...` | findings ou aucun finding |
| Docker | `docker run ... --generate` | 12 hashs |
| Compose | `docker compose ...` | API healthy |

---

## 10. Rappel

- Le scanner est **défensif** : il signale, il ne corrige pas.
- Il ne supprime jamais de Secret, PVC, PV ou volume.
- Les valeurs sensibles sont redactées dans les rapports.
- Pour toute intervention sur un cluster Systalink, lis d’abord
  `/home/ghost/Scrits_all/RUNBOOK-recovery.md` et respecte les règles
  d’exploitation (pas de suppression sans confirmation, `datacloud-ntx-v2` en
  lecture seule).
