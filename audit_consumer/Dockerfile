FROM python:3.14.7-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS build

WORKDIR /build
COPY audit_consumer/requirements.txt ./
RUN python -m pip wheel --no-cache-dir --require-hashes --wheel-dir /wheels -r requirements.txt

FROM python:3.14.7-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

WORKDIR /app

COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index /wheels/* && rm -rf /wheels
RUN addgroup --system authclaw && adduser --system --ingroup authclaw authclaw

COPY --chown=authclaw:authclaw audit_consumer/ .
COPY --chown=authclaw:authclaw backend/app/__init__.py /app/backend/app/__init__.py
COPY --chown=authclaw:authclaw backend/app/services/__init__.py /app/backend/app/services/__init__.py
COPY --chown=authclaw:authclaw backend/app/services/audit_utils.py /app/backend/app/services/audit_utils.py
ENV PYTHONPATH=/app/backend

EXPOSE 9108

USER authclaw

CMD ["python", "consumer.py"]
