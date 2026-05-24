# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir hatchling

# Copy project
COPY pyproject.toml README.md ./
COPY raiguard/ ./raiguard/

# Install rai-guard
RUN pip install --no-cache-dir .

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

COPY --from=base /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=base /usr/local/bin /usr/local/bin
COPY raiguard/ ./raiguard/

# Non-root user
RUN useradd -m -u 1000 raiguard && chown -R raiguard /app
USER raiguard

# Expose proxy port
EXPOSE 8000

# Environment
ENV RAI_UPSTREAM_URL=https://api.openai.com \
    RAI_BLOCK_ON_FAIL=true \
    RAI_SCORE_THRESHOLD=0.7

# Default: start proxy server
CMD ["uvicorn", "raiguard.proxy:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--timeout-graceful-shutdown", "10"]
