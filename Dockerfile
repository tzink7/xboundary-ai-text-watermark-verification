FROM python:3.12-slim

# openssl CLI (signing/verify), dig (DNS lookups), CA roots (d= HTTPS fetch).
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Only third-party dep: `reedsolo`, and only for tools/fairoze.py (fairoze-1
# payload Reed-Solomon). Everything else is standard-library.
COPY tools/requirements.txt ./tools/requirements.txt
RUN pip install --no-cache-dir -r tools/requirements.txt

COPY tools/   ./tools/
COPY demo/    ./demo/
COPY samples/ ./samples/

# Cloud Run / Render inject PORT and route to 0.0.0.0; server.py reads both.
ENV HOST=0.0.0.0
EXPOSE 8080

# Never run as root; keep the in-image keys/ dir writable for the env-var key.
RUN useradd -m app \
    && rm -f demo/keys/*.pem demo/keys/*.der \
    && chown -R app /app
USER app

CMD ["python3", "demo/server.py"]
