# Stage 1: Build — install dependencies with build tools
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc rustc cargo libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pyproject.toml VERSION README.md ./
COPY src/ src/
# spec/ is needed at wheel-build time because pyproject.toml force-includes
# spec/presets.yaml into the bulwark package (ADR-023 / G-PRESETS-007).
COPY spec/ spec/
RUN pip install --no-cache-dir --prefix=/install ".[dashboard,testing]"

# Reinstall the package itself into /install
COPY . .
RUN pip install --no-cache-dir --no-deps --prefix=/install "."


# Stage 2: Runtime — clean image, no build tools, non-root user
FROM python:3.11-slim

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application files (respects .dockerignore)
COPY . .

# Create non-root user and set ownership
RUN groupadd -r bulwark && useradd -r -g bulwark -d /app bulwark \
    && mkdir -p /app/reports \
    && chown -R bulwark:bulwark /app

USER bulwark

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:3000/healthz')" || exit 1

CMD ["python", "-m", "bulwark.dashboard", "--host", "0.0.0.0", "--port", "3000"]
