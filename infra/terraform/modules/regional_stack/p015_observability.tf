locals {
  rds_identifier = try(aws_db_instance.postgres_primary[0].identifier, aws_db_instance.postgres_replica[0].identifier)
  alarm_context  = "owner=${var.alarm_owner}; acknowledge_within=${var.alarm_acknowledgement_minutes}m; escalation=${var.alarm_escalation_path}"
  alarm_tags = {
    Owner                  = var.alarm_owner
    AcknowledgementMinutes = tostring(var.alarm_acknowledgement_minutes)
    EscalationPath         = var.alarm_escalation_path
  }
  operations_events = {
    ecs_deployment_failed = {
      description = "ECS deployment circuit breaker reported a failed deployment"
      pattern = {
        source        = ["aws.ecs"]
        "detail-type" = ["ECS Deployment State Change"]
        detail        = { eventName = ["SERVICE_DEPLOYMENT_FAILED"], clusterArn = [aws_ecs_cluster.main.arn] }
      }
    }
    rds_failure = {
      description = "RDS reported an availability-impacting failure event"
      pattern = {
        source        = ["aws.rds"]
        "detail-type" = ["RDS DB Instance Event"]
        detail        = { SourceIdentifier = [local.rds_identifier], EventCategories = ["failure"] }
      }
    }
    rds_failover = {
      description = "RDS reported a failover event"
      pattern = {
        source        = ["aws.rds"]
        "detail-type" = ["RDS DB Instance Event"]
        detail        = { SourceIdentifier = [local.rds_identifier], EventCategories = ["failover"] }
      }
    }
    redis_event = {
      description = "ElastiCache reported a replication-group availability event"
      pattern = {
        source        = ["aws.elasticache"]
        "detail-type" = ["ElastiCache Replication Group Event"]
        detail        = { SourceIdentifier = [aws_elasticache_replication_group.redis.id] }
      }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_running_below_minimum" {
  for_each = local.scalable_services

  alarm_name          = "${var.name}-${each.key}-running-below-minimum"
  alarm_description   = "CRITICAL: running task count is below the availability floor; runbook docs/runbooks/P0_14_P0_15_OPERATIONS.md"
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  period              = 60
  statistic           = "Minimum"
  threshold           = local.ha_environment ? var.service_min_capacity[each.key] : 1
  treat_missing_data  = "breaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = local.ecs_service_names_for_scaling[each.key]
  }
  tags = merge(var.tags, local.alarm_tags, { Severity = "critical" })
}

resource "aws_cloudwatch_metric_alarm" "rds" {
  for_each = {
    high_cpu         = { metric = "CPUUtilization", operator = "GreaterThanThreshold", threshold = 85, statistic = "Average", periods = 3 }
    low_memory       = { metric = "FreeableMemory", operator = "LessThanThreshold", threshold = 268435456, statistic = "Minimum", periods = 3 }
    low_storage      = { metric = "FreeStorageSpace", operator = "LessThanThreshold", threshold = 10737418240, statistic = "Minimum", periods = 3 }
    high_connections = { metric = "DatabaseConnections", operator = "GreaterThanThreshold", threshold = floor(var.rds_max_connections * 0.8), statistic = "Maximum", periods = 3 }
    deadlocks        = { metric = "Deadlocks", operator = "GreaterThanThreshold", threshold = 0, statistic = "Sum", periods = 1 }
  }

  alarm_name          = "${var.name}-rds-${replace(each.key, "_", "-")}"
  alarm_description   = "RDS ${each.value.metric} crossed its actionable threshold; runbook docs/runbooks/P0_14_P0_15_OPERATIONS.md"
  namespace           = "AWS/RDS"
  metric_name         = each.value.metric
  comparison_operator = each.value.operator
  evaluation_periods  = each.value.periods
  datapoints_to_alarm = each.value.periods
  period              = 60
  statistic           = each.value.statistic
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  dimensions          = { DBInstanceIdentifier = local.rds_identifier }
  tags                = merge(var.tags, local.alarm_tags, { Severity = contains(["low_memory", "low_storage"], each.key) ? "critical" : "warning" })
}

resource "aws_cloudwatch_metric_alarm" "rds_replica_lag" {
  count = var.create_db_replica ? 1 : 0

  alarm_name          = "${var.name}-rds-replica-lag"
  alarm_description   = "Cross-region replica lag exceeded 60 seconds; runbook docs/runbooks/P0_14_P0_15_OPERATIONS.md"
  namespace           = "AWS/RDS"
  metric_name         = "ReplicaLag"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  period              = 60
  statistic           = "Maximum"
  threshold           = 60
  treat_missing_data  = "breaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  dimensions          = { DBInstanceIdentifier = local.rds_identifier }
  tags                = merge(var.tags, local.alarm_tags, { Severity = "critical" })
}

resource "aws_cloudwatch_metric_alarm" "redis" {
  for_each = {
    memory_pressure = { metric = "DatabaseMemoryUsageCountedForEvictPercentage", threshold = 80, statistic = "Maximum", dimensions = { ReplicationGroupId = aws_elasticache_replication_group.redis.id } }
    engine_cpu      = { metric = "EngineCPUUtilization", threshold = 85, statistic = "Average", dimensions = { ReplicationGroupId = aws_elasticache_replication_group.redis.id, Role = "Primary" } }
  }

  alarm_name          = "${var.name}-redis-${replace(each.key, "_", "-")}"
  alarm_description   = "Redis ${each.value.metric} crossed its availability threshold; runbook docs/runbooks/P0_14_P0_15_OPERATIONS.md"
  namespace           = "AWS/ElastiCache"
  metric_name         = each.value.metric
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  period              = 60
  statistic           = each.value.statistic
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  dimensions          = each.value.dimensions
  tags                = merge(var.tags, local.alarm_tags, { Severity = each.key == "memory_pressure" ? "critical" : "warning" })
}

resource "aws_cloudwatch_metric_alarm" "redis_replication_lag" {
  count = 2

  alarm_name          = "${var.name}-redis-node-${count.index + 1}-replication-lag"
  alarm_description   = "Redis node replication lag exceeded five seconds; runbook docs/runbooks/P0_14_P0_15_OPERATIONS.md"
  namespace           = "AWS/ElastiCache"
  metric_name         = "ReplicationLag"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  period              = 60
  statistic           = "Maximum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  dimensions = {
    CacheClusterId = element(tolist(aws_elasticache_replication_group.redis.member_clusters), count.index)
    CacheNodeId    = "0001"
  }
  tags = merge(var.tags, local.alarm_tags, { Severity = "critical" })
}

resource "aws_cloudwatch_metric_alarm" "redis_evictions" {
  count = 2

  alarm_name          = "${var.name}-redis-node-${count.index + 1}-evictions"
  alarm_description   = "Redis node evicted data; inspect memory pressure and scaling"
  namespace           = "AWS/ElastiCache"
  metric_name         = "Evictions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  dimensions = {
    CacheClusterId = element(tolist(aws_elasticache_replication_group.redis.member_clusters), count.index)
    CacheNodeId    = "0001"
  }
  tags = merge(var.tags, local.alarm_tags, { Severity = "warning" })
}

resource "aws_cloudwatch_log_group" "operations_event" {
  for_each          = local.operations_events
  name              = "/authclaw/${var.name}/events/${replace(each.key, "_", "-")}"
  retention_in_days = var.service_log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_event_rule" "operations" {
  for_each      = local.operations_events
  name          = "${var.name}-${replace(each.key, "_", "-")}"
  description   = each.value.description
  event_pattern = jsonencode(each.value.pattern)
  tags          = var.tags
}

resource "aws_cloudwatch_event_target" "operations_log" {
  for_each = local.operations_events
  rule     = aws_cloudwatch_event_rule.operations[each.key].name
  arn      = aws_cloudwatch_log_group.operations_event[each.key].arn
}

resource "aws_cloudwatch_log_resource_policy" "operations_events" {
  policy_name = "${var.name}-operations-events"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "arn:${data.aws_partition.current.partition}:logs:${var.region}:${var.aws_account_id != "" ? var.aws_account_id : "*"}:log-group:/authclaw/${var.name}/events/*:*"
    }]
  })
}

resource "aws_cloudwatch_log_metric_filter" "operations_event" {
  for_each       = local.operations_events
  name           = "${var.name}-${replace(each.key, "_", "-")}"
  log_group_name = aws_cloudwatch_log_group.operations_event[each.key].name
  pattern        = ""
  metric_transformation {
    name      = replace(title(replace(each.key, "_", " ")), " ", "")
    namespace = "AuthClaw/Operations"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "operations_event" {
  for_each = local.operations_events

  alarm_name          = "${var.name}-${replace(each.key, "_", "-")}"
  alarm_description   = "CRITICAL: ${each.value.description}; runbook docs/runbooks/P0_14_P0_15_OPERATIONS.md"
  namespace           = "AuthClaw/Operations"
  metric_name         = replace(title(replace(each.key, "_", " ")), " ", "")
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  tags                = merge(var.tags, local.alarm_tags, { Severity = "critical" })
}

resource "aws_cloudwatch_metric_alarm" "vpc_endpoint_packet_drop" {
  for_each = aws_vpc_endpoint.interface

  alarm_name          = "${var.name}-endpoint-${each.key}-packet-drop"
  alarm_description   = "PrivateLink endpoint is dropping packets; runbook docs/runbooks/P0_14_P0_15_OPERATIONS.md"
  namespace           = "AWS/PrivateLinkEndpoints"
  metric_name         = "PacketsDropped"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  dimensions = {
    "Endpoint Type"   = "Interface"
    "Service Name"    = each.value.service_name
    "VPC Endpoint Id" = each.value.id
    "VPC Id"          = each.value.vpc_id
  }
  tags = merge(var.tags, local.alarm_tags, { Severity = "critical" })
}

resource "aws_cloudwatch_metric_alarm" "audit_integrity" {
  for_each = {
    outbox_stalled        = { metric = "authclaw_gateway_audit_outbox_oldest_age_seconds", namespace = "AuthClaw/Gateway", threshold = 300, periods = 5 }
    outbox_failures       = { metric = "authclaw_gateway_audit_outbox_failures_total", namespace = "AuthClaw/Gateway", threshold = 0, periods = 1 }
    sequence_gaps         = { metric = "audit_consumer_sequence_gaps_total", namespace = "AuthClaw/Audit", threshold = 0, periods = 1 }
    clickhouse_drift      = { metric = "audit_consumer_mirror_drift_total", namespace = "AuthClaw/Audit", threshold = 0, periods = 1 }
    replay_failures       = { metric = "audit_consumer_clickhouse_insert_failures_total", namespace = "AuthClaw/Audit", threshold = 0, periods = 1 }
    verification_failures = { metric = "audit_consumer_verification_failures_total", namespace = "AuthClaw/Audit", threshold = 0, periods = 1 }
  }

  alarm_name          = "${var.name}-audit-${replace(each.key, "_", "-")}"
  alarm_description   = "CRITICAL: audit integrity/delivery signal ${each.value.metric}; runbook docs/runbooks/P0_14_P0_15_OPERATIONS.md"
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = each.value.periods
  datapoints_to_alarm = each.value.periods
  period              = 60
  statistic           = "Maximum"
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  tags                = merge(var.tags, local.alarm_tags, { Severity = "critical" })
}

resource "aws_cloudwatch_log_group" "rds_postgresql" {
  name              = "/aws/rds/instance/${local.rds_identifier}/postgresql"
  retention_in_days = var.service_log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_log_metric_filter" "rds_slow_query" {
  name           = "${var.name}-rds-slow-query"
  log_group_name = aws_cloudwatch_log_group.rds_postgresql.name
  pattern        = "\"duration:\""
  metric_transformation {
    name      = "SlowQueryCount"
    namespace = "AuthClaw/RDS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_slow_query" {
  alarm_name          = "${var.name}-rds-slow-query"
  alarm_description   = "PostgreSQL emitted sustained slow-query log entries; inspect Performance Insights and the runbook"
  namespace           = "AuthClaw/RDS"
  metric_name         = "SlowQueryCount"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  ok_actions          = var.edge_alarm_action_arns
  tags                = merge(var.tags, local.alarm_tags, { Severity = "warning" })
}

resource "aws_cloudwatch_dashboard" "services" {
  dashboard_name = "${var.name}-services"
  dashboard_body = jsonencode({ widgets = [
    {
      type = "metric", width = 12, height = 8
      properties = {
        title = "ECS desired, running, pending, and restarts", region = var.region, view = "timeSeries"
        metrics = flatten([for service in keys(local.scalable_services) : [
          ["ECS/ContainerInsights", "DesiredTaskCount", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", local.ecs_service_names_for_scaling[service], { label = "${service} desired", stat = "Maximum" }],
          [".", "RunningTaskCount", ".", ".", ".", ".", { label = "${service} running", stat = "Minimum" }],
          [".", "PendingTaskCount", ".", ".", ".", ".", { label = "${service} pending", stat = "Maximum" }],
          [".", "RestartCount", ".", ".", ".", ".", { label = "${service} restarts", stat = "Sum" }],
        ]])
      }
    },
    {
      type = "metric", width = 12, height = 8
      properties = {
        title = "ECS CPU and memory utilization", region = var.region, view = "timeSeries"
        metrics = flatten([for service in keys(local.scalable_services) : [
          ["AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", local.ecs_service_names_for_scaling[service], { label = "${service} CPU", stat = "Average" }],
          [".", "MemoryUtilization", ".", ".", ".", ".", { label = "${service} memory", stat = "Average" }],
        ]])
      }
    },
    {
      type = "metric", width = 24, height = 8
      properties = {
        title = "ALB target health, requests, errors, and latency", region = var.region, view = "timeSeries"
        metrics = flatten([for service in keys(local.public_services) : [
          ["AWS/ApplicationELB", "HealthyHostCount", "LoadBalancer", aws_lb.service[service].arn_suffix, "TargetGroup", aws_lb_target_group.service[service].arn_suffix, { label = "${service} healthy", stat = "Minimum" }],
          [".", "UnHealthyHostCount", ".", ".", ".", ".", { label = "${service} unhealthy", stat = "Maximum" }],
          [".", "RequestCount", "LoadBalancer", aws_lb.service[service].arn_suffix, { label = "${service} requests", stat = "Sum" }],
          [".", "HTTPCode_Target_4XX_Count", ".", ".", { label = "${service} 4xx", stat = "Sum" }],
          [".", "HTTPCode_Target_5XX_Count", ".", ".", { label = "${service} 5xx", stat = "Sum" }],
          [".", "TargetResponseTime", ".", ".", { label = "${service} p95 latency", stat = "p95" }],
        ]])
      }
    },
    {
      type = "metric", width = 24, height = 5
      properties = {
        title   = "Deployment and infrastructure failure events", region = var.region, view = "timeSeries"
        metrics = [for event in keys(local.operations_events) : ["AuthClaw/Operations", replace(title(replace(event, "_", " ")), " ", ""), { label = event, stat = "Sum" }]]
      }
    },
  ] })
}

resource "aws_cloudwatch_dashboard" "data" {
  dashboard_name = "${var.name}-data"
  dashboard_body = jsonencode({ widgets = [
    {
      type = "metric", width = 12, height = 8
      properties = {
        title   = "RDS capacity, connections, locks, and replica lag", region = var.region, view = "timeSeries"
        metrics = [for metric in ["CPUUtilization", "FreeableMemory", "FreeStorageSpace", "DatabaseConnections", "DiskQueueDepth", "Deadlocks", "ReplicaLag", "TransactionLogsDiskUsage"] : ["AWS/RDS", metric, "DBInstanceIdentifier", local.rds_identifier, { stat = contains(["CPUUtilization", "DatabaseConnections"], metric) ? "Average" : "Maximum" }]]
      }
    },
    {
      type = "metric", width = 12, height = 8
      properties = {
        title = "Redis memory, eviction, connections, replication, CPU, and network", region = var.region, view = "timeSeries"
        metrics = concat(
          [
            ["AWS/ElastiCache", "DatabaseMemoryUsageCountedForEvictPercentage", "ReplicationGroupId", aws_elasticache_replication_group.redis.id, { label = "group memory pressure", stat = "Maximum" }],
            [".", "EngineCPUUtilization", ".", ".", "Role", "Primary", { label = "primary engine CPU", stat = "Average" }],
            [".", ".", ".", ".", ".", "Replica", { label = "replica engine CPU", stat = "Average" }],
          ],
          flatten([for node in range(2) : [
            ["AWS/ElastiCache", "Evictions", "CacheClusterId", element(tolist(aws_elasticache_replication_group.redis.member_clusters), node), "CacheNodeId", "0001", { label = "node ${node + 1} evictions", stat = "Sum" }],
            [".", "CurrConnections", ".", ".", ".", ".", { label = "node ${node + 1} connections", stat = "Maximum" }],
            [".", "ReplicationLag", ".", ".", ".", ".", { label = "node ${node + 1} replication lag", stat = "Maximum" }],
            [".", "NetworkBytesIn", ".", ".", ".", ".", { label = "node ${node + 1} network in", stat = "Sum" }],
            [".", "NetworkBytesOut", ".", ".", ".", ".", { label = "node ${node + 1} network out", stat = "Sum" }],
          ]])
        )
      }
    },
    {
      type = "metric", width = 24, height = 8
      properties = {
        title = "Audit transport, retries, DLQ, sequence gaps, drift, replay, and chain verification", region = var.region, view = "timeSeries"
        metrics = concat(
          local.audit_sqs_enabled ? [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", aws_sqs_queue.audit[0].name, { label = "backlog", stat = "Maximum" }],
            [".", "ApproximateAgeOfOldestMessage", ".", ".", { label = "oldest age", stat = "Maximum" }],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", aws_sqs_queue.audit_dlq[0].name, { label = "DLQ depth", stat = "Maximum" }],
          ] : [],
          [for metric in ["audit_consumer_retries_total", "audit_consumer_dlq_publish_failures_total", "audit_consumer_sequence_gaps_total", "audit_consumer_mirror_drift_total", "audit_consumer_clickhouse_insert_failures_total", "audit_consumer_verification_failures_total"] : ["AuthClaw/Audit", metric, "Environment", var.authclaw_env, "Service", "audit_consumer", { stat = "Sum" }]]
        )
      }
    },
  ] })
}

resource "aws_cloudwatch_dashboard" "network" {
  dashboard_name = "${var.name}-network"
  dashboard_body = jsonencode({ widgets = [{
    type = "metric", width = 24, height = 8
    properties = {
      title = "NAT and VPC endpoint availability", region = var.region, view = "timeSeries"
      metrics = concat(
        flatten([for key, nat in aws_nat_gateway.main : [
          ["AWS/NATGateway", "BytesOutToDestination", "NatGatewayId", nat.id, { label = "NAT ${key} bytes out", stat = "Sum" }],
          [".", "ErrorPortAllocation", ".", ".", { label = "NAT ${key} port errors", stat = "Sum" }],
          [".", "PacketsDropCount", ".", ".", { label = "NAT ${key} drops", stat = "Sum" }],
        ]]),
        [for key, endpoint in aws_vpc_endpoint.interface : ["AWS/PrivateLinkEndpoints", "PacketsDropped", "Endpoint Type", "Interface", "Service Name", endpoint.service_name, "VPC Endpoint Id", endpoint.id, "VPC Id", endpoint.vpc_id, { label = "${key} drops", stat = "Sum" }]]
      )
    }
  }] })
}
