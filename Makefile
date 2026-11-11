.PHONY: install test lint bench docker-build api

install:
	pip install -r requirements-dev.txt

test:
	pytest -q

lint:
	ruff check smart_hash_cracker.py api.py tests bench

bench:
	python bench/benchmark.py

docker-build:
	docker build -t smart-hash-tool:local .

api:
	uvicorn api:app --host 0.0.0.0 --port 8000
