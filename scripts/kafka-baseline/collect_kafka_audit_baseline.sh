#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

# AuthClaw Kafka audit stream baseline collector.
#
# This script captures repeatable Kafka observability signals for the current audit
# transport. It intentionally does not alter any Kafka transport configuration.
#
# Usage:
#   AUTHCLAW_BASELINE_ENV=production \
#   KAFKA_BOOTSTRAP=pkc-xxxxx.us-east-1.aws.confluent.cloud:9092 \
#   ./scripts/kafka-baseline/collect_kafka_audit_baseline.sh ./evidence/kafka-baseline

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ROOT_DIR

OUTPUT_DIR="${1:-${ROOT_DIR}/artifacts/kafka-baseline}"
TIMESTAMP="$(date -u +'%Y-%m-%dT%H%M%SZ')"
readonly TIMESTAMP

mkdir -p "${OUTPUT_DIR}/${TIMESTAMP}"
OUT="${OUTPUT_DIR}/${TIMESTAMP}"
export OUT

KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-${KAFKA_BOOTSTRAP_SERVERS:-${KAFKA_BROKERS:-localhost:9092}}}"
KAFKA_TOPICS="${KAFKA_TOPICS:-${KAFKA_TOPIC_GATEWAY_TRAFFIC:-gateway.traffic},${KAFKA_TOPIC_AUDIT_EVENTS:-audit.events},audit.deadletter}"
KAFKA_GROUP_ID="${KAFKA_GROUP_ID:-authclaw-audit-consumer}"
KAFKA_TOPICS_GATEWAY="${KAFKA_TOPIC_GATEWAY_TRAFFIC:-gateway.traffic}"
KAFKA_TOPICS_AUDIT="${KAFKA_TOPIC_AUDIT_EVENTS:-audit.events}"
KAFKA_TOPICS_DLQ="${KAFKA_DLQ_TOPIC:-audit.deadletter}"
METRICS_WINDOW_SECONDS="${METRICS_WINDOW_SECONDS:-600}"
MESSAGE_SAMPLE_LIMIT="${MESSAGE_SAMPLE_LIMIT:-2000}"
MESSAGE_SAMPLE_BYTES_LIMIT="${MESSAGE_SAMPLE_BYTES_LIMIT:-524288}"
DB_URL="${DATABASE_URL:-${POSTGRES_URL:-}}"
CLICKHOUSE_URL="${CLICKHOUSE_URL:-${CLICKHOUSE_HTTP_URL:-}}"
AUTHCLAW_BASELINE_ENV="${AUTHCLAW_BASELINE_ENV:-unknown}"
ENVIRONMENT_TAG="${AUTHCLAW_BASELINE_ENV}"
TENANT_GROUPING_LIMIT="${TENANT_GROUPING_LIMIT:-25}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
AWS_MSK_CLUSTER_ARN="${AWS_MSK_CLUSTER_ARN:-}"

for tool in jq awk sed tr date awk timeout; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "WARN: required helper missing: ${tool}" >&2
  fi
done

require_command() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "ERROR: missing required command: ${name}" >&2
    return 1
  fi
}

detect_kafka_cli() {
  if command -v rpk >/dev/null 2>&1; then
    echo "rpk"
    return 0
  fi
  if command -v kafka-topics.sh >/dev/null 2>&1; then
    echo "kafka"
    return 0
  fi
  return 1
}

topic_list() {
  tr ',' ' ' <<< "${KAFKA_TOPICS}"
}

write_metadata() {
  cat > "${OUT}/metadata.json" <<EOF
{
  "collected_at_utc": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "command_invoked": "$0",
  "run_window_seconds": ${METRICS_WINDOW_SECONDS},
  "environment": "${ENVIRONMENT_TAG}",
  "kafka_bootstrap": "${KAFKA_BOOTSTRAP}",
  "kafka_topics": [$(echo "$(topic_list)" | tr ' ' '\n' | sed '/^$/d' | awk '{printf "\"%s\",", $0}' | sed 's/,$//')],
  "kafka_consumer_group": "${KAFKA_GROUP_ID}",
  "sample_limit": ${MESSAGE_SAMPLE_LIMIT},
  "message_sample_bytes_limit": ${MESSAGE_SAMPLE_BYTES_LIMIT},
  "tenant_grouping_limit": ${TENANT_GROUPING_LIMIT},
  "notes": [
    "NO production payload is captured in this run.",
    "Raw tenant payload bytes are sampled as length only.",
    "Metrics and API calls may require elevated service account roles in the target environment."
  ]
}
EOF
}

collect_cli_inventory() {
  {
    echo "kafka_bootstrap=${KAFKA_BOOTSTRAP}"
    echo "kafka_topics=${KAFKA_TOPICS}"
    echo "kafka_group=${KAFKA_GROUP_ID}"
    echo "collect_window_seconds=${METRICS_WINDOW_SECONDS}"
  } > "${OUT}/collection.env"
}

collect_tool_outputs() {
  local topic=""
  local cli
  cli="$(detect_kafka_cli || true)"
  if [[ "${cli}" == "rpk" ]]; then
    {
      echo "# rpk topic list"
      rpk topic list -X brokers="${KAFKA_BOOTSTRAP}" || true
      echo "# rpk cluster info"
      rpk cluster info -X brokers="${KAFKA_BOOTSTRAP}" || true
    } > "${OUT}/kafka_cluster_inventory.txt"

    for topic in $(topic_list); do
      {
        echo "# rpk topic describe ${topic}"
        rpk topic describe "${topic}" -X brokers="${KAFKA_BOOTSTRAP}" || true
        echo
      } >> "${OUT}/kafka_cluster_inventory.txt"
    done
  elif [[ "${cli}" == "kafka" ]]; then
    local topics_cli="--describe --topic"
    {
      echo "# kafka-topics --list"
      kafka-topics.sh --bootstrap-server "${KAFKA_BOOTSTRAP}" --list || true
      echo "# kafka-consumer-groups --list"
      kafka-consumer-groups.sh --bootstrap-server "${KAFKA_BOOTSTRAP}" --list || true
      echo "# kafka-consumer-groups --describe"
      kafka-consumer-groups.sh --bootstrap-server "${KAFKA_BOOTSTRAP}" --describe --all-groups --state || true
    } > "${OUT}/kafka_cluster_inventory.txt"
  else
    echo "# no kafka CLI found, manual collection required" > "${OUT}/kafka_cluster_inventory.txt"
  fi
}

collect_topic_metrics() {
  local cli
  cli="$(detect_kafka_cli || true)"
  for topic in $(topic_list); do
    if [[ "${cli}" == "rpk" ]]; then
      echo "topic=${topic}" >> "${OUT}/topic_baseline.csv"
      {
        rpk topic describe "${topic}" -X brokers="${KAFKA_BOOTSTRAP}" 2>/dev/null || true
      } >> "${OUT}/topic_baseline_raw_${topic}.txt"
    else
      {
        kafka-topics.sh --bootstrap-server "${KAFKA_BOOTSTRAP}" --describe --topic "${topic}" || true
      } >> "${OUT}/topic_baseline_raw_${topic}.txt"
    fi
  done
  cat > "${OUT}/topic_baseline.csv" <<EOF
metric_name,topic,value,source
EOF
}

collect_consumer_group_state() {
  local out_file="${OUT}/consumer_groups.txt"
  > "${out_file}"
  if command -v kafka-consumer-groups.sh >/dev/null 2>&1; then
    kafka-consumer-groups.sh --bootstrap-server "${KAFKA_BOOTSTRAP}" --all-groups --describe >> "${out_file}" 2>&1 || true
    if [[ -n "${KAFKA_GROUP_ID}" ]]; then
      kafka-consumer-groups.sh --bootstrap-server "${KAFKA_BOOTSTRAP}" --describe --group "${KAFKA_GROUP_ID}" >> "${out_file}" 2>&1 || true
    fi
  elif command -v rpk >/dev/null 2>&1; then
    rpk group describe "${KAFKA_GROUP_ID}" -X brokers="${KAFKA_BOOTSTRAP}" >> "${out_file}" 2>&1 || true
    rpk group status -X brokers="${KAFKA_BOOTSTRAP}" >> "${out_file}" 2>&1 || true
  else
    echo "ERROR: kafka-consumer-groups.sh and rpk both unavailable" >> "${out_file}"
  fi
}

extract_message_observability() {
  local topic="$1"
  local sample_file="${OUT}/sample_${topic}.ndjson"
  local metrics_file="${OUT}/message_size_${topic}.jsonl"

  if command -v kcat >/dev/null 2>&1; then
    kcat -C \
      -b "${KAFKA_BOOTSTRAP}" \
      -t "${topic}" \
      -o end \
      -c "${MESSAGE_SAMPLE_LIMIT}" \
      -J \
      -u \
      -f '%t\t%p\t%o\t%s\t%b\n' \
      > "${sample_file}" 2>/dev/null || true
    return
  fi

  {
    echo "kcat not installed; raw-message extraction skipped for ${topic}."
    echo "Install kcat to measure message size + per-tenant bytes."
  } > "${sample_file}"
  cp "${sample_file}" "${metrics_file}"
}

compute_message_profile() {
  local topic="$1"
  local sample_file="${OUT}/sample_${topic}.ndjson"
  local output_file="${OUT}/message_profile_${topic}.json"

  if command -v jq >/dev/null 2>&1 && [[ -s "${sample_file}" ]] && grep -q '{' "${sample_file}"; then
    awk '
      /^$/ {next}
      {
        # Attempt to handle plain JSON payload lines and fallback lines.
        line = $0
        split(line, fields, "\t")
        if (NF >= 6) {
          bytes[NR] = length(fields[4])
          tenant = ""
          if (match(fields[6], /tenant_id[^:]*:[^\"]*\"([^\"]+)\"/, m)) tenant = m[1]
          if (tenant != "" && count_tenant[tenant] < "'"${TENANT_GROUPING_LIMIT}"'") {
            tenant_bytes[tenant] = tenant_bytes[tenant] + length(fields[4])
            count_tenant[tenant]++
          }
        }
      }
      END {
        n = asorti(bytes, idx)
        if (n == 0) {
          print "{"
          print "  \"count\":0,"
          print "  \"avg_bytes\":0,"
          print "  \"max_bytes\":0,"
          print "  \"tenant_top_bytes\":{}"
          print "}"
          exit
        }
        sum=0; max=0
        for (i in bytes) {
          sum += bytes[i]
          if (bytes[i] > max) max = bytes[i]
        }
        printf "{\n"
        printf "  \"count\": %d,\n", n
        printf "  \"avg_bytes\": %.2f,\n", sum / n
        printf "  \"max_bytes\": %d,\n", max
        printf "  \"tenant_top_bytes\": {\n"
        for (k in tenant_bytes) printf "    \"%s\": %d,\n", k, tenant_bytes[k]
        print "  }\n}"
      }
    ' "${sample_file}" > "${output_file}"
  else
    cat > "${output_file}" <<EOF
{
  "count": 0,
  "avg_bytes": 0,
  "max_bytes": 0,
  "tenant_top_bytes": {},
  "notes": [
    "message sampling requires kcat + jq in environment"
  ]
}
EOF
  fi
}

collect_broker_exported_metrics() {
  local now_s=0
  local start_s=0
  now_s="$(date +%s)"
  start_s="$((now_s - METRICS_WINDOW_SECONDS))"
  if command -v curl >/dev/null 2>&1; then
    for endpoint in \
      "${GATEWAY_METRICS_URL:-}" \
      "${BACKEND_METRICS_URL:-}" \
      "${AUDIT_CONSUMER_METRICS_URL:-}"; do
      if [[ -n "${endpoint}" ]]; then
        curl -fsS "${endpoint}/metrics" > "${OUT}/$(echo "${endpoint}" | tr -dc '[:alnum:]-_').txt" || true
      fi
    done
  fi
  {
    echo "window_start_utc=$(date -u -d "@${start_s}" +'%Y-%m-%dT%H:%M:%SZ')"
    echo "window_end_utc=$(date -u -d "@${now_s}" +'%Y-%m-%dT%H:%M:%SZ')"
    echo "collector_window_seconds=${METRICS_WINDOW_SECONDS}"
  } > "${OUT}/metrics_window.txt"
}

collect_kafka_broker_retention_runtime() {
  local out_file="${OUT}/retention_and_replay_signals.txt"
  {
    echo "# Topic retention config"
    for topic in $(topic_list); do
      case "$(detect_kafka_cli || true)" in
        rpk)
          rpk topic describe "${topic}" -X brokers="${KAFKA_BOOTSTRAP}" || true
          ;;
        kafka)
          kafka-topics.sh --bootstrap-server "${KAFKA_BOOTSTRAP}" --describe --topic "${topic}" || true
          ;;
        *)
          echo "cli missing for ${topic}"
          ;;
      esac
    done
    echo
    echo "# Replay / DLQ policy references"
    echo "KAFKA audit consumer code path (audit_consumer.py) uses auto_offset_reset=earliest and does not commit before a successful write."
  } > "${out_file}"
}

collect_replay_and_dedup_signals() {
  local out_file="${OUT}/replay_and_dedup_sql.md"
  if [[ -n "${DB_URL}" ]]; then
    {
      echo "# PostgreSQL replay and tenant replay evidence"
      echo ""
      echo "Audit outbox pending (authoritative, includes source-of-truth status):"
      psql "${DB_URL}" -At -F',' <<'SQL'
SELECT
  tenant_id,
  COUNT(*) AS pending_outbox_rows,
  MIN(created_at) AS oldest_pending_created_at
FROM audit_outbox
WHERE published_at IS NULL
GROUP BY tenant_id
ORDER BY pending_outbox_rows DESC;
SQL
    } > "${out_file}"
    if [[ -n "${CLICKHOUSE_URL}" ]]; then
      {
        echo ""
        echo "ClickHouse replay and latest append point:"
        curl -sS "${CLICKHOUSE_URL}?query=SELECT+tenant_id%2C%20max%28tenant_sequence%29+%2C+max%28created_at%29+FROM+authclaw.audit_events+GROUP+BY+tenant_id+ORDER+BY+tenant_id+LIMIT+100"
      } >> "${out_file}"
    else
      echo "CLICKHOUSE_URL not set; manual verification runbook notes retained in ${out_file}." >> "${out_file}"
    fi
  else
    echo "# PostgreSQL URL not set" > "${out_file}"
    echo "Set DATABASE_URL in environment to capture replay and outbox backlog evidence." >> "${out_file}"
  fi
}

collect_aws_cost_and_ops() {
  local out_file="${OUT}/aws_cost_and_ops.md"
  {
    echo "# AWS Kafka/streaming baseline collection"
    if [[ -z "${AWS_REGION}" ]]; then
      echo "AWS_REGION not set; cannot collect region-scoped cost metrics."
      return
    fi
    echo "AWS region: ${AWS_REGION}"
    if [[ -n "${AWS_MSK_CLUSTER_ARN}" ]] && command -v aws >/dev/null 2>&1; then
      aws kafka get-cluster-arn --region "${AWS_REGION}" --cluster-arn "${AWS_MSK_CLUSTER_ARN}" || true
    fi
    echo ""
    echo "The commands below are for live execution in staging/prod only:"
    echo "1) aws kafka describe-cluster --cluster-arn"
    echo "2) aws kafka get-bootstrap-brokers --cluster-arn"
    echo "3) aws cloudwatch list-metrics --namespace AWS/Kafka --region ${AWS_REGION}"
    echo "4) aws cloudwatch get-metric-statistics for broker-level and topic-level throughput, error, and consumer-lag metrics"
    echo "5) aws ce get-cost-and-usage for Amazon MSK (or Kinesis equivalent if used)"
    echo "6) aws ce get-cost-and-usage for VPC Interface Endpoint / NAT / Cross-AZ transfer as required"
    echo "Do not run this file outside a controlled credentials boundary."
  } > "${out_file}"
}

build_results() {
  local out_file="${OUT}/kafka_baseline_result_template.md"
  cat > "${out_file}" <<'EOF'
# Kafka baseline report

This file is a generated starting point for production evidence. Fill measured values from the sibling artifact files and keep
the raw command outputs untouched for auditability.

## Evidence metadata
- run_id:
- environment:
- region/account:
- collection_started_utc:
- collection_completed_utc:
- collector:
- bootstrap_servers:
- topics:
- consumer_group:

## Required evidence and source files
- topic topology and retention: `topic_baseline_raw_*.txt`
- consumer state and lag: `consumer_groups.txt`
- message sampling profile: `message_profile_*.json`
- app counters: `gateway_metrics.txt`, `backend_metrics.txt`, `audit_consumer_metrics.txt`
- replay signals: `replay_and_dedup_sql.md`
- kafka config/retention: `retention_and_replay_signals.txt`
- AWS cost & operations: `aws_cost_and_ops.md`
- env snapshot: `metadata.json`

## Representative-load KPIs (populate)
1. Peak events/sec:
2. Average events/sec:
3. Average event size bytes:
4. Maximum event size bytes:
5. Traffic per tenant:
6. Kafka partition count:
7. Current producer error rate:
8. Consumer throughput:
9. Consumer lag:
10. Required retention period:
11. Current replay usage:
12. ordering scope:
13. DLQ/retry volume:
14. Kafka infrastructure and operational cost:
15. Live-access limitations / assumptions:

## Live data limitations
- Any values marked `LIVE-MISSING` indicate missing tooling credentials or intentionally skipped commands.
- Never copy local-replay metrics as production numbers.

EOF
}

collect_app_metrics() {
  for endpoint_name in gateway backend audit_consumer; do
    local var=""; local out_file=""
    case "${endpoint_name}" in
      gateway)
        var="${GATEWAY_METRICS_URL:-}"
        out_file="gateway_metrics.txt"
        ;;
      backend)
        var="${BACKEND_METRICS_URL:-}"
        out_file="backend_metrics.txt"
        ;;
      audit_consumer)
        var="${AUDIT_CONSUMER_METRICS_URL:-}"
        out_file="audit_consumer_metrics.txt"
        ;;
    esac
    if [[ -n "${var}" ]] && command -v curl >/dev/null 2>&1; then
      curl -fsS "${var}/metrics" > "${OUT}/${out_file}" || true
    fi
  done
}

main() {
  echo "output_dir=${OUT}"
  write_metadata
  collect_tool_outputs
  collect_topic_metrics
  collect_consumer_group_state
  for topic in $(topic_list); do
    extract_message_observability "${topic}"
    compute_message_profile "${topic}"
  done
  collect_app_metrics
  collect_broker_exported_metrics
  collect_kafka_broker_retention_runtime
  collect_replay_and_dedup_signals
  collect_aws_cost_and_ops
  build_results
  echo "Kafka audit baseline collection complete in ${OUT}"
}

main "$@"
