# Malicious URL Detection API: production image (Render, or any container host)
# Python version = the one the model was trained with (models/model_metadata.json -> versions.python 3.14.3)
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MODEL_DIR=/app/models \
    TRUSTED_LIST_ENABLED=true \
    LOG_LEVEL=INFO \
    PORT=10000

# LightGBM needs the OpenMP runtime, which the slim image does not include
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) dependencies first (cached layer), exact versions the model was trained with
COPY requirements-api.txt .
RUN pip install -r requirements-api.txt

# 2) only the code and the model files the API needs
COPY src/ src/
COPY api/ api/
COPY models/best_model.joblib models/feature_extractor.joblib models/model_metadata.json models/
COPY data/processed/feature_list.json data/processed/feature_list.json

# 3) run as a non-root user
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '10000') + '/health', timeout=4)" || exit 1

# shell form so ${PORT} (set by Render) is expanded
CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-10000}
