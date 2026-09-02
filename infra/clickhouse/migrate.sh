#!/usr/bin/env bash
set -euo pipefail

schema_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
client=(
  clickhouse-client
  --host "${CLICKHOUSE_HOST:-localhost}"
  --port "${CLICKHOUSE_NATIVE_PORT:-9000}"
  --user "${CLICKHOUSE_USER:-authclaw}"
  --password "${CLICKHOUSE_PASSWORD:-authclaw}"
)

query() {
  "${client[@]}" --format TSVRaw --query "$1"
}

"${client[@]}" --multiquery < "${schema_dir}/init.sql"

required_columns="$(query "
  SELECT count()
  FROM system.columns
  WHERE database = 'authclaw'
    AND table = 'audit_events'
    AND name IN ('tenant_sequence', 'idempotency_key', 'chain_version', 'canonical_payload')
")"

if [[ "${required_columns}" == "4" ]]; then
  echo "ClickHouse audit schema is current."
  exit 0
fi

if [[ "${required_columns}" != "0" ]]; then
  echo "Refusing partial ClickHouse audit upgrade (${required_columns}/4 ACL-21 columns present)." >&2
  exit 1
fi

legacy_tables="$(query "
  SELECT count()
  FROM system.tables
  WHERE database = 'authclaw'
    AND name IN ('audit_events_acl21_legacy', 'audit_events_daily_acl21_legacy')
")"
if [[ "${legacy_tables}" != "0" ]]; then
  echo "Refusing to overwrite an existing ACL-21 legacy ClickHouse backup." >&2
  exit 1
fi

legacy_rows="$(query "SELECT count() FROM authclaw.audit_events")"
"${client[@]}" --multiquery --query "
  DROP VIEW IF EXISTS authclaw.audit_events_daily_mv;
  RENAME TABLE
    authclaw.audit_events TO authclaw.audit_events_acl21_legacy,
    authclaw.audit_events_daily TO authclaw.audit_events_daily_acl21_legacy;
"
"${client[@]}" --multiquery < "${schema_dir}/init.sql"

test "$(query "
  SELECT count()
  FROM system.columns
  WHERE database = 'authclaw'
    AND table = 'audit_events'
    AND name IN ('tenant_sequence', 'idempotency_key', 'chain_version', 'canonical_payload')
")" = "4"

echo "Upgraded ClickHouse audit schema; preserved ${legacy_rows} derived rows in authclaw.audit_events_acl21_legacy."
echo "Replay PostgreSQL audit records into the clean ClickHouse mirror before resuming ingestion."
