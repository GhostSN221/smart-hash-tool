# Image officielle légère
FROM python:3.11-slim

# Sécurité : user non-root
RUN useradd -m appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY smart_hash_cracker.py .
COPY wordlist.txt .

RUN chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["python3", "smart_hash_cracker.py"]
