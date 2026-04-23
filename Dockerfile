# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM python:3.12-slim AS builder

# Install system dependencies
# libc6-dev and libc6-i386 provide the dynamic linkers and libc needed for rootfs
# curl is needed to download ATT&CK STIX data
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libffi-dev \
    libc6-dev \
    libc6-i386 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /build

# Copy project files needed for dependency installation
COPY pyproject.toml uv.lock README.md ./

# Install dependencies with uv
RUN uv sync --frozen --no-install-project --no-dev

# Copy source code
COPY src/ ./src/

# Install the detonate package itself
RUN uv sync --frozen --no-dev

# Download ATT&CK STIX data
RUN mkdir -p data/attack_stix && \
    curl -sL https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
    -o data/attack_stix/enterprise-attack.json

# Populate Qiling Linux rootfs from container filesystem
# Qiling needs dynamic linker and libc to emulate Linux binaries
# We install libc6-dev and libc6-i386 above to ensure these files exist
RUN mkdir -p data/rootfs/x86_linux/lib data/rootfs/x8664_linux/lib64 data/rootfs/x8664_linux/lib \
    data/rootfs/x86_linux/etc data/rootfs/x8664_linux/etc && \
    # x86_64 rootfs: copy dynamic linker and essential libraries
    cp /lib64/ld-linux-x86-64.so.2 data/rootfs/x8664_linux/lib64/ && \
    cp -r /lib/x86_64-linux-gnu data/rootfs/x8664_linux/lib/ && \
    # x86 rootfs: copy 32-bit dynamic linker (may be in /lib or /lib32 on some systems)
    ( [ -f /lib/ld-linux.so.2 ] && cp /lib/ld-linux.so.2 data/rootfs/x86_linux/lib/ ) || \
    ( [ -f /lib32/ld-linux.so.2 ] && cp /lib32/ld-linux.so.2 data/rootfs/x86_linux/lib/ ) || \
    true && \
    # Copy 32-bit libraries if available
    ( [ -d /lib/i386-linux-gnu ] && cp -r /lib/i386-linux-gnu data/rootfs/x86_linux/lib/ ) || \
    ( [ -d /lib32 ] && cp -r /lib32 data/rootfs/x86_linux/ ) || \
    true && \
    # Create minimal /etc with passwd file (some binaries expect it)
    echo "root:x:0:0:root:/root:/bin/bash" > data/rootfs/x86_linux/etc/passwd && \
    cp data/rootfs/x86_linux/etc/passwd data/rootfs/x8664_linux/etc/passwd && \
    # Create tmp directories for sample execution (will be mounted as writable)
    mkdir -p data/rootfs/x86_linux/tmp data/rootfs/x8664_linux/tmp && \
    chown -R 1000:1000 data/rootfs/x86_linux/tmp data/rootfs/x8664_linux/tmp && \
    # Validation: verify rootfs has required files
    echo "Validating x86_64 rootfs..." && \
    test -f data/rootfs/x8664_linux/lib64/ld-linux-x86-64.so.2 && \
    ls data/rootfs/x8664_linux/lib/x86_64-linux-gnu/libc.so* >/dev/null && \
    echo "x86_64 rootfs OK" && \
    echo "Validating x86 rootfs (best effort)..." && \
    ( test -f data/rootfs/x86_linux/lib/ld-linux.so.2 && echo "x86 rootfs OK" || echo "x86 rootfs: ld-linux not found, may need manual setup" )

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

# Copy installed packages and project from builder
COPY --from=builder /build/.venv /app/.venv
COPY --from=builder /build/src /app/src
COPY --from=builder /build/data /app/data

# Fix shebang paths in venv scripts and .pth files to point to /app/.venv instead of /build/.venv
RUN find /app/.venv/bin -type f -exec sed -i 's|/build/.venv|/app/.venv|g' {} \; && \
    find /app/.venv/lib -name "*.pth" -exec sed -i 's|/build/.venv|/app/.venv|g' {} \; && \
    find /app/.venv -name "_editable_impl_*.pth" -exec sed -i 's|/build/src|/app/src|g' {} \;

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
HEALTHCHECK --interval=15s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf http://127.0.0.1:8000/health || exit 1

# Expose API port
EXPOSE 8000

# Entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["serve"]
