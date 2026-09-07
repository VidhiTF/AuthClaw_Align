"""
clickhouse_writer.py — Writes audit event rows to ClickHouse with retry logic.
"""

import logging
import os
import time
from typing import Any

import clickhouse_connect

logger = logging.getLogger(__name__)


def _bounded_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def get_client(
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
) -> clickhouse_connect.driver.Client:
    """Create and return a ClickHouse HTTP client."""
    return clickhouse_connect.get_client(
        host=host,
        port=port,
        database=database,
        username=username,
        password=password,
        connect_timeout=_bounded_float("CLICKHOUSE_CONNECT_TIMEOUT_SECONDS", 3.0, 0.5, 30.0),
        send_receive_timeout=_bounded_float("CLICKHOUSE_READ_TIMEOUT_SECONDS", 10.0, 1.0, 60.0),
    )


# Column order must match the DDL in infra/clickhouse/init.sql.
_COLUMNS = [
    "record_id",
    "tenant_id",
    "tenant_sequence",
    "idempotency_key",
    "chain_version",
    "canonical_payload",
    "timestamp",
    "actor_id",
    "actor_type",
    "action",
    "policy_id",
    "provider",
    "model",
    "reason",
    "prompt_count",
    "request_size",
    "response_status",
    "duration_ms",
    "frameworks_affected",
    "execution_trace",
    "request_id",
    "prior_hash",
    "integrity_hash",
]


def insert_audit_event(
    client: clickhouse_connect.driver.Client,
    row: dict[str, Any],
    max_retries: int | None = None,
    retry_delay: float | None = None,
    max_retry_delay: float | None = None,
) -> bool:
    """
    Insert a single audit event row into authclaw.audit_events.

    Retries up to max_retries times on transient errors.
    Returns False when the event already exists and no insert is needed.
    """
    attempts = max_retries if max_retries is not None else _bounded_int("CLICKHOUSE_MAX_ATTEMPTS", 3, 1, 5)
    base_delay = retry_delay if retry_delay is not None else _bounded_float("CLICKHOUSE_RETRY_BASE_SECONDS", 0.5, 0.05, 5.0)
    delay_cap = max_retry_delay if max_retry_delay is not None else _bounded_float("CLICKHOUSE_RETRY_MAX_SECONDS", 2.0, 0.1, 10.0)
    attempts = max(1, min(attempts, 5))
    base_delay = max(0.0, min(base_delay, 5.0))
    delay_cap = max(base_delay, min(delay_cap, 10.0))

    if audit_event_exists(client, str(row.get("record_id", ""))):
        logger.info("Skipping duplicate audit event record_id=%s", row.get("record_id"))
        return False

    data = [[row.get(col) for col in _COLUMNS]]

    for attempt in range(1, attempts + 1):
        try:
            client.insert(
                table="authclaw.audit_events",
                data=data,
                column_names=_COLUMNS,
            )
            logger.debug(
                "Inserted audit event record_id=%s",
                row.get("record_id"),
            )
            return True
        except Exception as exc:  # noqa: BLE001
            if attempt == attempts:
                logger.error(
                    "Failed to insert audit event after %d attempts: %s", attempts, type(exc).__name__
                )
                raise
            delay = min(base_delay * (2 ** (attempt - 1)), delay_cap)
            logger.warning(
                "ClickHouse insert attempt %d failed: error_type=%s retrying_in_seconds=%.2f",
                attempt,
                type(exc).__name__,
                delay,
            )
            time.sleep(delay)
    return False


def audit_event_exists(client: clickhouse_connect.driver.Client, record_id: str) -> bool:
    """Return True when ClickHouse already has this audit record_id."""
    if not record_id:
        return False
    result = client.query(
        """
        SELECT count()
        FROM authclaw.audit_events
        WHERE record_id = {record_id:UUID}
        """,
        parameters={"record_id": record_id},
    )
    rows = result.result_rows
    return bool(rows and rows[0][0] > 0)


def get_prior_hash(
    client: clickhouse_connect.driver.Client,
    tenant_id: str,
) -> str:
    """
    Return the integrity_hash of the most recent audit record for this tenant.
    Returns 'GENESIS' if no prior record exists.
    """
    result = client.query(
        """
        SELECT integrity_hash
        FROM authclaw.audit_events
        WHERE tenant_id = {tenant_id:UUID}
        ORDER BY tenant_sequence DESC
        LIMIT 1
        """,
        parameters={"tenant_id": tenant_id},
    )
    rows = result.result_rows
    if rows:
        return rows[0][0] or "GENESIS"
    return "GENESIS"


def get_tenant_tail(
    client: clickhouse_connect.driver.Client,
    tenant_id: str,
) -> tuple[int, str]:
    """Return the deterministic sequence and hash at the ClickHouse tail."""
    result = client.query(
        """
        SELECT tenant_sequence, integrity_hash
        FROM authclaw.audit_events
        WHERE tenant_id = {tenant_id:UUID}
        ORDER BY tenant_sequence DESC
        LIMIT 1
        """,
        parameters={"tenant_id": tenant_id},
    )
    rows = result.result_rows
    if rows:
        return int(rows[0][0]), rows[0][1] or "GENESIS"
    return 0, "GENESIS"
