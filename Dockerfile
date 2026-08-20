# Multi-stage hardened non-root Dockerfile (CIS Docker Benchmark & OWASP Compliant)
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir .

# Stage 2: Hardened Runtime Environment
FROM python:3.12-slim AS runner

WORKDIR /app

# Configurable Timezone via environment variable (Default: America/Mexico_City / GMT-6)
ENV TZ=America/Mexico_City \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/bin:${PATH}" \
    PYTHONPATH="/install/lib/python3.12/site-packages:${PYTHONPATH}"

# Install tzdata for timezone support and create unprivileged system user (UID 10001)
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser && \
    mkdir -p /app/data /tmp && \
    chown -R 10001:10001 /app/data /tmp

# Copy installed dependencies from builder stage
COPY --from=builder /usr/local/lib/python3.12/site-packages /install/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /install/bin

# Copy app code and configurations
COPY app/ ./app
COPY config/ ./config
COPY alembic.ini ./

# Set restrictive permissions
RUN chown -R 10001:10001 /app && \
    chmod -R 755 /app

USER 10001:10001

EXPOSE 8000

# Native Granian ASGI Server Entrypoint
ENTRYPOINT ["granian", "--interface", "asgi", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "app.main:app"]
