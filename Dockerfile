FROM python:3.12-slim

# openssl CLI (signing/verify), dig (DNS lookups), CA roots (d= HTTPS fetch).
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Only third-party dep for the base image: `reedsolo`, and only for
# tools/fairoze.py (fairoze-1 payload Reed-Solomon). Everything else is stdlib.
COPY tools/requirements.txt ./tools/requirements.txt
RUN pip install --no-cache-dir -r tools/requirements.txt

# Optional: live synthid-1 detection. `--build-arg SYNTHID_LIVE=1` installs
# CPU-only torch + transformers (~400 MB) and pre-bakes the Qwen tokenizer, so
# the demo's verify endpoint scores ANY pasted text instead of falling back to
# the pre-computed samples/synthid-1/verify-scores.json table. Also set
# SYNTHID_KEYS_JSON (Cloud Run secret) and SYNTHID_VERIFY_MODE=live at deploy.
ARG SYNTHID_LIVE=0
ARG SYNTHID_TOKENIZER=Qwen/Qwen2.5-3B-Instruct
COPY tools/requirements-synthid.txt ./tools/requirements-synthid.txt
RUN if [ "$SYNTHID_LIVE" = "1" ]; then \
        pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
        && pip install --no-cache-dir -r tools/requirements-synthid.txt \
        && python3 -c "from transformers import AutoTokenizer; \
             AutoTokenizer.from_pretrained('${SYNTHID_TOKENIZER}').save_pretrained('/app/hf/tokenizer')" ; \
    fi
ENV SYNTHID_TOKENIZER_BUNDLED=/app/hf/tokenizer

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
