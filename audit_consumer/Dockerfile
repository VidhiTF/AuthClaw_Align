FROM python:3.14.7-slim

WORKDIR /app

COPY audit_consumer/requirements.txt ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt
RUN addgroup --system authclaw && adduser --system --ingroup authclaw authclaw

COPY --chown=authclaw:authclaw audit_consumer/ .
COPY --chown=authclaw:authclaw backend/app/__init__.py /app/backend/app/__init__.py
COPY --chown=authclaw:authclaw backend/app/services/__init__.py /app/backend/app/services/__init__.py
COPY --chown=authclaw:authclaw backend/app/services/audit_utils.py /app/backend/app/services/audit_utils.py
ENV PYTHONPATH=/app/backend

EXPOSE 9108

USER authclaw

CMD ["python", "consumer.py"]
