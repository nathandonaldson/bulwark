FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (cache layer)
COPY pyproject.toml VERSION README.md ./
COPY src/ src/
RUN pip install --no-cache-dir ".[dashboard]"

# Copy remaining files (static assets, spec, etc.)
COPY . .

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:3000/healthz')" || exit 1

CMD ["python", "-m", "bulwark.dashboard", "--host", "0.0.0.0", "--port", "3000"]
