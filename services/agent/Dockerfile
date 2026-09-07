FROM python:3.14.3-slim@sha256:5e59aae31ff0e87511226be8e2b94d78c58f05216efda3b07dbbed938ec8583b AS build

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-model.txt ./
RUN python -m pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.txt -r requirements-model.txt

FROM python:3.14.3-slim@sha256:5e59aae31ff0e87511226be8e2b94d78c58f05216efda3b07dbbed938ec8583b

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends poppler-utils tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /install /usr/local

COPY . .

RUN useradd --create-home --shell /usr/sbin/nologin authclaw \
    && mkdir -p /app/logs /app/watched_documents /app/scratch \
    && chown -R authclaw:authclaw /app

USER authclaw

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health/ready', timeout=3)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
