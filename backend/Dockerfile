FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[prod]"

COPY . .

# Default: run the API server.
# Workers and Beat override this via fly.worker.toml / fly.beat.toml [processes].
CMD ["uvicorn", "backend.app.main:app_with_middleware", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
