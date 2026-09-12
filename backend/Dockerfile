# ==============================================================================
# CIPHER AI Backend - Production Dockerfile
# Python 3.12+ with FastAPI & PostgreSQL
# ==============================================================================

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies for asyncpg and C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies in a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Final minimal runtime image
FROM python:3.12-slim AS runner

WORKDIR /app

# Install runtime PostgreSQL client library and curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root unprivileged security analyst user
RUN groupadd -r cipher && useradd -r -g cipher -s /bin/false cipher

# Copy application source code
COPY . .

# Set permissions
RUN chown -R cipher:cipher /app

USER cipher

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Launch production server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
