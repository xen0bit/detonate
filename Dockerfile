# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM python:3.12-slim AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy project files
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry install --no-root --only main

# Copy source code
COPY src/ ./src/

# Download ATT&CK STIX data
RUN mkdir -p data/attack_stix && \
    curl -sL https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
    -o data/attack_stix/enterprise-attack.json

# Copy Qiling Linux rootfs (from submodule or manual copy)
COPY data/rootfs/x86_linux/ ./data/rootfs/x86_linux/
COPY data/rootfs/x8664_linux/ ./data/rootfs/x8664_linux/

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM python:3.12-slim AS runtime

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 detonate && \
    useradd --uid 1000 --gid detonate --shell /bin/bash --create-home detonate

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /build/.venv /app/.venv
COPY --from=builder /build/src /app/src
COPY --from=builder /build/data /app/data

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    DETONATE_DATABASE=/var/lib/detonate/detonate.db \
    DETONATE_ROOTFS=/app/data/rootfs

# Create data directories
RUN mkdir -p /var/lib/detonate /output /samples && \
    chown -R detonate:nogroup /var/lib/detonate /output /app

# Switch to non-root user
USER detonate

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -sf http://127.0.0.1:8000/api/v1/health || exit 1

# Expose API port
EXPOSE 8000

# Entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["serve"]
