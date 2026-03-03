# Image officielle légère
FROM python:3.11-slim

# Sécurité : user non-root
RUN useradd -m appuser

WORKDIR /app

# Copier le script
COPY smart_hash_cracker.py .

# Droits propres
RUN chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["python3", "smart_hash_cracker.py"]
