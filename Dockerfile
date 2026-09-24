# syntax=docker/dockerfile:1
# Recovery-card key reconstruction service.
# Pure Python standard library -> no pip install, builds offline.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /srv/recovery-card

# Copy the application and the acceptance script/tests (the image doubles
# as the image used by the one-shot "verify" compose service).
COPY app/ ./app/
COPY tests/ ./tests/
COPY verify.py ./verify.py

# Run as an unprivileged user. Sources stay owner-writable so the one-shot
# verify service can emit __pycache__; the web container additionally mounts
# its root filesystem read-only.
RUN useradd --system --uid 10001 appuser \
    && chown -R appuser:root /srv/recovery-card \
    && chmod -R o-w /srv/recovery-card
USER appuser

EXPOSE 8080

# Container-level health check (Compose references service_healthy too).
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD ["python", "-m", "app.healthcheck"]

CMD ["python", "-m", "app.server"]
