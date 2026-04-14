FROM python:3.11-slim

# Build deps for garak's Rust-based dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc rustc cargo libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (cache layer)
COPY pyproject.toml VERSION README.md ./
COPY src/ src/
RUN pip install --no-cache-dir ".[dashboard,testing]"

# Copy remaining files (static assets, spec, etc.)
COPY . .

# Reinstall so the package reflects any files from COPY . .
RUN pip install --no-cache-dir --no-deps "."

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:3000/healthz')" || exit 1

CMD ["python", "-m", "bulwark.dashboard", "--host", "0.0.0.0", "--port", "3000"]
