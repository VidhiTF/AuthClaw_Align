FROM python:3.14.3-slim AS backend

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        poppler-utils \
        tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-model.txt ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt -r requirements-model.txt

COPY . .

RUN useradd --create-home --shell /usr/sbin/nologin authclaw \
    && mkdir -p /app/logs /app/watched_documents /app/scratch \
    && chown -R authclaw:authclaw /app

USER authclaw

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health/ready', timeout=3)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
