locals {
  audit_sqs_enabled           = var.audit_stream_transport == "sqs_fifo"
  audit_sqs_producer_services = toset(["backend", "gateway"])
  audit_sqs_environment = [
    { name = "AUDIT_STREAM_TRANSPORT", value = var.audit_stream_transport },
  ]
  audit_sqs_producer_environment = local.audit_sqs_enabled ? concat(local.audit_sqs_environment, [
    { name = "SQS_AUDIT_QUEUE_URL", value = aws_sqs_queue.audit[0].url }
  ]) : local.audit_sqs_environment
  audit_sqs_consumer_environment = local.audit_sqs_enabled ? [
    { name = "SQS_LONG_POLL_SECONDS", value = tostring(var.audit_sqs_long_poll_seconds) },
    { name = "SQS_MAX_MESSAGES", value = tostring(var.audit_sqs_max_messages) },
    { name = "SQS_VISIBILITY_TIMEOUT_SECONDS", value = tostring(var.audit_sqs_visibility_timeout_seconds) }
  ] : []
  audit_sqs_task_role_arns = local.audit_sqs_enabled ? { for service in setunion(local.audit_sqs_producer_services, toset(["audit_consumer"])) : service => aws_iam_role.application_task[service].arn } : {}
}

resource "aws_sqs_queue" "audit_dlq" {
  count = local.audit_sqs_enabled ? 1 : 0

  name                              = "${var.name}-audit-dlq.fifo"
  fifo_queue                        = true
  content_based_deduplication       = false
  deduplication_scope               = "messageGroup"
  fifo_throughput_limit             = "perMessageGroupId"
  kms_master_key_id                 = aws_kms_key.main.arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = var.audit_sqs_dlq_retention_seconds
  tags                              = var.tags
}

resource "aws_sqs_queue" "audit" {
  count = local.audit_sqs_enabled ? 1 : 0

  name                              = "${var.name}-audit.fifo"
  fifo_queue                        = true
  content_based_deduplication       = false
  deduplication_scope               = "messageGroup"
  fifo_throughput_limit             = "perMessageGroupId"
  kms_master_key_id                 = aws_kms_key.main.arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = var.audit_sqs_retention_seconds
  visibility_timeout_seconds        = var.audit_sqs_visibility_timeout_seconds
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.audit_dlq[0].arn
    maxReceiveCount     = var.audit_sqs_max_receive_count
  })
  tags = var.tags
}

resource "aws_sqs_queue_redrive_allow_policy" "audit_dlq" {
  count = local.audit_sqs_enabled ? 1 : 0

  queue_url = aws_sqs_queue.audit_dlq[0].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.audit[0].arn]
  })
}

resource "aws_sqs_queue_policy" "audit_tls" {
  count = local.audit_sqs_enabled ? 1 : 0

  queue_url = aws_sqs_queue.audit[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = aws_sqs_queue.audit[0].arn
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_sqs_queue_policy" "audit_dlq_tls" {
  count = local.audit_sqs_enabled ? 1 : 0

  queue_url = aws_sqs_queue.audit_dlq[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = aws_sqs_queue.audit_dlq[0].arn
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_iam_role_policy" "audit_sqs_producer" {
  for_each = local.audit_sqs_enabled ? local.audit_sqs_producer_services : toset([])

  name = "${var.name}-${each.key}-audit-sqs-producer"
  role = aws_iam_role.application_task[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"]
        Resource = aws_sqs_queue.audit[0].arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.main.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "sqs.${var.region}.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "audit_sqs_consumer" {
  count = local.audit_sqs_enabled ? 1 : 0

  name = "${var.name}-audit-consumer-sqs"
  role = aws_iam_role.application_task["audit_consumer"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl"
        ]
        Resource = aws_sqs_queue.audit[0].arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.main.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "sqs.${var.region}.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "audit_sqs" {
  for_each = local.audit_sqs_enabled ? {
    dlq_depth  = { queue = aws_sqs_queue.audit_dlq[0].name, metric = "ApproximateNumberOfMessagesVisible", threshold = var.audit_sqs_dlq_depth_alarm_threshold }
    dlq_age    = { queue = aws_sqs_queue.audit_dlq[0].name, metric = "ApproximateAgeOfOldestMessage", threshold = var.audit_sqs_dlq_age_alarm_seconds }
    main_age   = { queue = aws_sqs_queue.audit[0].name, metric = "ApproximateAgeOfOldestMessage", threshold = var.audit_sqs_main_age_alarm_seconds }
    main_depth = { queue = aws_sqs_queue.audit[0].name, metric = "ApproximateNumberOfMessagesVisible", threshold = var.audit_sqs_backlog_alarm_threshold }
  } : {}

  alarm_name          = "${var.name}-audit-sqs-${each.key}"
  alarm_description   = "AuthClaw audit SQS FIFO ${each.key} alarm; ${local.alarm_context}"
  namespace           = "AWS/SQS"
  metric_name         = each.value.metric
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  period              = 60
  statistic           = "Maximum"
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.audit_sqs_alarm_action_arns
  ok_actions          = var.audit_sqs_alarm_action_arns

  dimensions = {
    QueueName = each.value.queue
  }

  tags = merge(var.tags, local.alarm_tags, {
    Severity = contains(["dlq_depth", "dlq_age"], each.key) ? "critical" : "warning"
  })
}
