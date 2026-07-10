"""
clickhouse_writer.py — Writes audit event rows to ClickHouse with retry logic.
"""

import logging
import time
from typing import Any

import clickhouse_connect

logger = logging.getLogger(__name__)


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
    )


# Column order must match the DDL in infra/clickhouse/init.sql.
_COLUMNS = [
    "record_id",
    "tenant_id",
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
    max_retries: int = 3,
    retry_delay: float = 0.5,
) -> bool:
    """
    Insert a single audit event row into authclaw.audit_events.

    Retries up to max_retries times on transient errors.
    Returns False when the event already exists and no insert is needed.
    """
    if audit_event_exists(client, str(row.get("record_id", ""))):
        logger.info("Skipping duplicate audit event record_id=%s", row.get("record_id"))
        return False

    data = [[row.get(col) for col in _COLUMNS]]

    for attempt in range(1, max_retries + 1):
        try:
            client.insert(
                table="authclaw.audit_events",
                data=data,
                column_names=_COLUMNS,
            )
            logger.debug(
                "Inserted audit event record_id=%s tenant_id=%s",
                row.get("record_id"),
                row.get("tenant_id"),
            )
            return True
        except Exception as exc:  # noqa: BLE001
            if attempt == max_retries:
                logger.error(
                    "Failed to insert audit event after %d attempts: %s", max_retries, exc
                )
                raise
            logger.warning(
                "ClickHouse insert attempt %d failed: %s — retrying in %.1fs",
                attempt,
                exc,
                retry_delay,
            )
            time.sleep(retry_delay)
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
        ORDER BY timestamp DESC, record_id DESC
        LIMIT 1
        """,
        parameters={"tenant_id": tenant_id},
    )
    rows = result.result_rows
    if rows:
        return rows[0][0] or "GENESIS"
    return "GENESIS"
