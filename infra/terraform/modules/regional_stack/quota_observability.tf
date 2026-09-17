locals {
  quota_observability_enabled = length(var.quota_alert_sns_topic_arns) > 0
  quota_collector_config = yamlencode({
    receivers = {
      prometheus = {
        config = {
          scrape_configs = [for service in ["gateway", "agent"] : {
            job_name        = "authclaw-${service}-quota"
            scrape_interval = "15s"
            metrics_path    = "/health"
            params          = { metrics = ["true"] }
            scheme          = contains(local.tls_services, service) ? "https" : "http"
            dns_sd_configs = [{
              names = ["${service}.${local.namespace_name}"]
              type  = "A"
              port  = local.service_ports[service]
            }]
          }]
        }
      }
    }
    processors = { batch = {} }
    exporters = {
      prometheusremotewrite = {
        endpoint = "${aws_prometheus_workspace.quota[0].prometheus_endpoint}api/v1/remote_write"
        auth     = { authenticator = "sigv4auth" }
      }
    }
    extensions = {
      sigv4auth = {
        region  = var.region
        service = "aps"
      }
    }
    service = {
      extensions = ["sigv4auth"]
      pipelines = {
        metrics = {
          receivers  = ["prometheus"]
          processors = ["batch"]
          exporters  = ["prometheusremotewrite"]
        }
      }
    }
  })
}

resource "aws_prometheus_workspace" "quota" {
  count = local.quota_observability_enabled ? 1 : 0
  alias = "${var.name}-quota"
  tags  = var.tags
}

resource "aws_prometheus_rule_group_namespace" "quota" {
  count        = local.quota_observability_enabled ? 1 : 0
  name         = "authclaw-quota"
  workspace_id = aws_prometheus_workspace.quota[0].id
  data         = file("${path.module}/../../../observability/quota-alerts.yml")
}

resource "aws_iam_role" "quota_alertmanager" {
  count                = local.quota_observability_enabled ? 1 : 0
  name                 = "${var.name}-quota-alertmanager"
  permissions_boundary = var.iam_permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "aps.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.iam_account_id }
        ArnEquals    = { "aws:SourceArn" = aws_prometheus_workspace.quota[0].arn }
      }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "quota_alertmanager" {
  count = local.quota_observability_enabled ? 1 : 0
  role  = aws_iam_role.quota_alertmanager[0].id
  name  = "publish-approved-quota-alerts"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = var.quota_alert_sns_topic_arns
    }]
  })
}

resource "aws_prometheus_alert_manager_definition" "quota" {
  count        = local.quota_observability_enabled ? 1 : 0
  workspace_id = aws_prometheus_workspace.quota[0].id
  definition = yamlencode({
    alertmanager_config = {
      route = {
        receiver        = "quota-sns"
        group_by        = ["alertname", "severity"]
        group_wait      = "30s"
        group_interval  = "5m"
        repeat_interval = "4h"
      }
      receivers = [{
        name = "quota-sns"
        sns_configs = [for topic in var.quota_alert_sns_topic_arns : {
          topic_arn     = topic
          role_arn      = aws_iam_role.quota_alertmanager[0].arn
          send_resolved = true
          sigv4         = { region = var.region }
        }]
      }]
    }
  })
}

resource "aws_cloudwatch_log_group" "quota_collector" {
  count             = local.quota_observability_enabled ? 1 : 0
  name              = "/authclaw/${var.name}/quota-metrics-collector"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_iam_role" "quota_collector_execution" {
  count                = local.quota_observability_enabled ? 1 : 0
  name                 = "${var.name}-quota-collector-exec"
  permissions_boundary = var.iam_permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.iam_account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ecs:${var.region}:${local.iam_account_id}:*" }
      }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "quota_collector_execution" {
  count = local.quota_observability_enabled ? 1 : 0
  role  = aws_iam_role.quota_collector_execution[0].id
  name  = "collector-startup"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.quota_collector[0].arn}:*"
      }, {
      Effect   = "Allow"
      Action   = ["ecr-public:GetAuthorizationToken", "sts:GetServiceBearerToken"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "quota_collector" {
  count                = local.quota_observability_enabled ? 1 : 0
  name                 = "${var.name}-quota-collector-runtime"
  permissions_boundary = var.iam_permissions_boundary_arn
  assume_role_policy   = aws_iam_role.quota_collector_execution[0].assume_role_policy
  tags                 = var.tags
}

resource "aws_iam_role_policy" "quota_collector" {
  count = local.quota_observability_enabled ? 1 : 0
  role  = aws_iam_role.quota_collector[0].id
  name  = "remote-write-quota-metrics"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["aps:RemoteWrite"]
      Resource = aws_prometheus_workspace.quota[0].arn
    }]
  })
}

resource "aws_ecs_task_definition" "quota_collector" {
  count                    = local.quota_observability_enabled ? 1 : 0
  family                   = "${var.name}-quota-metrics-collector"
  requires_compatibilities = local.ecs_launch_compatibilities
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.quota_collector_execution[0].arn
  task_role_arn            = aws_iam_role.quota_collector[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.ecs_ec2_graviton.enabled ? "ARM64" : "X86_64"
  }

  volume { name = "collector-tmp" }

  container_definitions = jsonencode([{
    name                   = "quota-metrics-collector"
    image                  = var.quota_metrics_collector_image
    essential              = true
    cpu                    = 256
    memory                 = 512
    readonlyRootFilesystem = true
    privileged             = false
    environment            = [{ name = "AOT_CONFIG_CONTENT", value = local.quota_collector_config }]
    mountPoints            = [{ sourceVolume = "collector-tmp", containerPath = "/tmp", readOnly = false }]
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.quota_collector[0].name
        awslogs-region        = var.region
        awslogs-stream-prefix = "collector"
      }
    }
  }])
  tags = var.tags
}

resource "aws_ecs_service" "quota_collector" {
  count = local.quota_observability_enabled ? 1 : 0

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  name                   = "${var.name}-quota-metrics-collector"
  cluster                = aws_ecs_cluster.main.id
  task_definition        = aws_ecs_task_definition.quota_collector[0].arn
  desired_count          = 1
  launch_type            = var.ecs_ec2_graviton.enabled ? null : "FARGATE"
  enable_execute_command = false

  dynamic "capacity_provider_strategy" {
    for_each = var.ecs_ec2_graviton.enabled ? [1] : []
    content {
      capacity_provider = aws_ecs_capacity_provider.graviton[0].name
      weight            = 1
      base              = 0
    }
  }

  network_configuration {
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }

  depends_on = [aws_ecs_cluster_capacity_providers.main]
  tags       = var.tags
}

output "quota_observability" {
  value = local.quota_observability_enabled ? {
    workspace_id           = aws_prometheus_workspace.quota[0].id
    collector_service      = aws_ecs_service.quota_collector[0].name
    rule_namespace         = aws_prometheus_rule_group_namespace.quota[0].name
    alertmanager_receivers = var.quota_alert_sns_topic_arns
  } : null
}
