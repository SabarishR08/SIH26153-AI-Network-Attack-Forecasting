# ============================================================
# SIH26153 — AI-Based Network Attack Forecasting
# Multi-stage Dockerfile: dev + production
# ============================================================

# ── Base stage (shared) ─────────────────────────────────────
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Development stage ───────────────────────────────────────
FROM base AS development

# Install dev tools
RUN pip install --no-cache-dir ruff mypy

# Copy source code
COPY . .

# Create data directory
RUN mkdir -p /app/data

EXPOSE 5000

CMD ["python", "run.py", "--no-pipeline"]

# ── Production stage ────────────────────────────────────────
FROM base AS production

# Security: run as non-root
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy only what's needed for production
COPY integration/ /app/integration/
COPY repos/ /app/repos/
COPY data/ /app/data/
COPY run.py /app/
COPY docs/ /app/docs/

# Create writable data directory
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/status')" || exit 1

# Run with gunicorn
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "integration.app:app"]
