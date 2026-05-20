FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python deps
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

# Copy app code
COPY NOTICE ./
COPY scripts/ ./scripts/
COPY .github/workflows/reputation-backfill-supervisor.yml ./.github/workflows/reputation-backfill-supervisor.yml
COPY data/ ./data/
RUN mkdir -p ./content
COPY contracts/ ./contracts/
COPY foundry/src/ ./foundry/src/
COPY docs/LEGAL_AND_ASSET_POLICY.md ./docs/LEGAL_AND_ASSET_POLICY.md
COPY docs/hackathon-0g/README.md ./docs/hackathon-0g/README.md
COPY docs/hackathon-0g/assets/README.md ./docs/hackathon-0g/assets/README.md
COPY docs/hackathon-0g/hackquest-submission-proof.json ./docs/hackathon-0g/hackquest-submission-proof.json
COPY docs/hackathon-0g/mainnet-proof.json ./docs/hackathon-0g/mainnet-proof.json
COPY docs/hackathon-0g/node-pi-readiness-proof.json ./docs/hackathon-0g/node-pi-readiness-proof.json
COPY docs/hackathon-0g/x402-base-sepolia-settlement-proof.json ./docs/hackathon-0g/x402-base-sepolia-settlement-proof.json
COPY docs/hackathon-0g/veo3-flow-production-prompt.md ./docs/hackathon-0g/veo3-flow-production-prompt.md

# Expose Flask port
EXPOSE 8109

ENV HOST=0.0.0.0
ENV PORT=8109

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8109/api/healthz || exit 1

# Default: run the production WSGI server
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8109} guard0.app:app"]
