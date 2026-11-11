FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN useradd -m appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY smart_hash_cracker.py api.py wordlist.txt ./

RUN chown -R appuser:appuser /app

USER appuser
EXPOSE 8000

# Default: CLI mode
# Override with: docker run ... uvicorn api:app --host 0.0.0.0 --port 8000
ENTRYPOINT ["python3", "smart_hash_cracker.py"]
