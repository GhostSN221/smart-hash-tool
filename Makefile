.PHONY: install test lint bench scan self-scan k8s-scan docker-build api

NAMESPACE ?= default

install:
	pip install -r requirements-dev.txt

test:
	pytest -q

lint:
	ruff check smart_hash_cracker.py api.py credential_scanner.py tests bench

bench:
	python bench/benchmark.py

scan:
	python credential_scanner.py --path . --config .credential-scan.json --format text

self-scan:
	python credential_scanner.py --path . --config .credential-scan.json --format sarif --out credential-scan.sarif --fail-on error

k8s-scan:
	python credential_scanner.py --k8s --namespace $(NAMESPACE) --format text

docker-build:
	docker build -t smart-hash-tool:local .

api:
	uvicorn api:app --host 0.0.0.0 --port 8000
