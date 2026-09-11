# Stage 1: Build & Dependencies
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY pyrasec/ ./pyrasec/

RUN pip install --no-cache-dir --upgrade pip build && \
    pip install --no-cache-dir .

# Stage 2: Minimal Runtime
FROM python:3.12-slim-bookworm

# Create unprivileged application user
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -d /home/appuser -m -s /bin/false appuser

COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

USER appuser:appuser
WORKDIR /home/appuser

# Native container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python3", "-m", "pyrasec", "health"] || exit 1

ENTRYPOINT ["python3", "-m", "pyrasec"]
CMD ["--help"]
