#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

OUTPUT_DIR="${1:-${PWD}/artifacts/kafka-baseline-cost}"
mkdir -p "${OUTPUT_DIR}"
OUT="${OUTPUT_DIR}"

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [[ -z "${AWS_REGION}" ]]; then
  echo "ERROR: set AWS_REGION before running this script" >&2
  exit 1
fi

START_DATE="${START_DATE:-$(date -u -d '30 days ago' +%Y-%m-%d)}"
END_DATE="${END_DATE:-$(date -u +%Y-%m-%d)}"
MSK_CLUSTER_ARN="${AWS_MSK_CLUSTER_ARN:-}"

if [[ -z "${MSK_CLUSTER_ARN}" ]]; then
  echo "WARN: AWS_MSK_CLUSTER_ARN not set; cluster discovery step will be skipped" >&2
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "ERROR: aws cli required" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq required" >&2
  exit 2
fi

aws ce get-cost-and-usage \
  --time-period Start="${START_DATE}",End="${END_DATE}" \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon MSK","Amazon SQS","Amazon Kinesis","Amazon EC2","AWS KMS","Amazon S3","AWS Lambda","Amazon CloudWatch"]}}' \
  --region "${AWS_REGION}" \
  > "${OUT}/aws_cost_by_service.json"

{
  echo "window_start=${START_DATE}"
  echo "window_end=${END_DATE}"
  echo "region=${AWS_REGION}"
  echo "cluster_arn=${MSK_CLUSTER_ARN}"
} > "${OUT}/cost_window.env"

if [[ -n "${MSK_CLUSTER_ARN}" ]]; then
  aws kafka describe-cluster --region "${AWS_REGION}" --cluster-arn "${MSK_CLUSTER_ARN}" > "${OUT}/msk_describe_cluster.json"
  aws kafka get-bootstrap-brokers --region "${AWS_REGION}" --cluster-arn "${MSK_CLUSTER_ARN}" > "${OUT}/msk_bootstrap_brokers.json"
  aws kafka list-nodes --region "${AWS_REGION}" --cluster-arn "${MSK_CLUSTER_ARN}" > "${OUT}/msk_nodes.json"
  aws cloudwatch list-metrics --region "${AWS_REGION}" --namespace AWS/Kafka > "${OUT}/cloudwatch_kafka_metrics.json"
fi

{
  echo "# Example CloudWatch metric pulls for replay/lag/throughput."
  echo "# Replace <<TOPIC_NAME>> and <<CLUSTER_NAME>> from discovered cluster metadata."
  cat <<'EOF'
aws cloudwatch get-metric-statistics \
  --region "$AWS_REGION" \
  --namespace AWS/Kafka \
  --metric-name BytesInPerSec \
  --dimensions Name=Cluster Name=<<CLUSTER_NAME>> Name=Topic Name=<<TOPIC_NAME>> \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --period 60 \
  --statistics Average
EOF
} > "${OUT}/cloudwatch_example_commands.sh"

echo "Cost and ops evidence collected in ${OUT}"
