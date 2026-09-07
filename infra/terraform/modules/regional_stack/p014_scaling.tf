locals {
  ha_environment = contains(["staging", "stage", "production", "prod"], lower(trimspace(var.authclaw_env)))
  scalable_services = merge(
    local.service_configs,
    var.enable_audit_consumer ? { audit_consumer = {} } : {},
  )
  ecs_service_names_for_scaling = merge(
    { for service, resource in aws_ecs_service.public : service => resource.name },
    { for service, resource in aws_ecs_service.private : service => resource.name },
    var.enable_audit_consumer ? { audit_consumer = aws_ecs_service.audit_consumer[0].name } : {},
  )
  db_connection_budget_used = (
    var.service_max_capacity["backend"] * var.db_connections_per_task["backend"] +
    var.service_max_capacity["gateway"] * var.db_connections_per_task["gateway"] +
    var.service_max_capacity["agent"] * var.db_connections_per_task["agent"]
  )
  service_task_resources = {
    console        = { cpu = var.service_cpu, memory = var.service_memory }
    backend        = { cpu = var.backend_sidecar_task_cpu, memory = var.backend_sidecar_task_memory }
    gateway        = { cpu = var.gateway_sidecar_task_cpu, memory = var.gateway_sidecar_task_memory }
    agent          = { cpu = var.agent_sidecar_task_cpu, memory = var.agent_sidecar_task_memory }
    audit_consumer = { cpu = var.service_cpu, memory = var.service_memory }
  }
  minimum_task_cpu    = sum([for service in keys(local.scalable_services) : local.service_task_resources[service].cpu * var.service_min_capacity[service]])
  minimum_task_memory = sum([for service in keys(local.scalable_services) : local.service_task_resources[service].memory * var.service_min_capacity[service]])
  maximum_task_cpu    = sum([for service in keys(local.scalable_services) : local.service_task_resources[service].cpu * var.service_max_capacity[service]])
  maximum_task_memory = sum([for service in keys(local.scalable_services) : local.service_task_resources[service].memory * var.service_max_capacity[service]])
}

resource "terraform_data" "availability_and_connection_budget" {
  input = {
    maximum_runtime_connections = local.db_connection_budget_used
    operational_reserve         = var.rds_connection_reserve
    configured_max_connections  = var.rds_max_connections
  }

  lifecycle {
    precondition {
      condition     = !local.ha_environment || length(local.azs) >= 2
      error_message = "Staging and production require at least two Availability Zones."
    }
    precondition {
      condition     = !local.ha_environment || alltrue([for service in keys(local.scalable_services) : var.service_min_capacity[service] >= 2])
      error_message = "Every enabled staging/production service must retain at least two tasks."
    }
    precondition {
      condition     = alltrue([for service in keys(local.scalable_services) : var.service_max_capacity[service] >= var.service_min_capacity[service]])
      error_message = "Every service scaling maximum must be greater than or equal to its minimum."
    }
    precondition {
      condition     = local.db_connection_budget_used + var.rds_connection_reserve <= var.rds_max_connections
      error_message = "Maximum ECS database pools plus the operational reserve exceed rds_max_connections; reduce task maxima/pools or provide measured RDS capacity."
    }
    precondition {
      condition = !var.ecs_ec2_graviton.enabled || (
        floor(var.ecs_ec2_graviton.min_size / 2) * var.ecs_ec2_graviton.usable_cpu_units >= local.minimum_task_cpu &&
        floor(var.ecs_ec2_graviton.min_size / 2) * var.ecs_ec2_graviton.usable_memory_mib >= local.minimum_task_memory &&
        floor(var.ecs_ec2_graviton.max_size / 2) * var.ecs_ec2_graviton.usable_cpu_units >= local.maximum_task_cpu &&
        floor(var.ecs_ec2_graviton.max_size / 2) * var.ecs_ec2_graviton.usable_memory_mib >= local.maximum_task_memory
      )
      error_message = "ECS on EC2 must fit the minimum and maximum service task mixes in one half of the ASG after an AZ failure; increase min/max capacity or measured usable instance resources."
    }
  }
}

resource "aws_appautoscaling_target" "ecs" {
  for_each = local.scalable_services

  max_capacity       = var.service_max_capacity[each.key]
  min_capacity       = local.ha_environment ? var.service_min_capacity[each.key] : 1
  resource_id        = "service/${aws_ecs_cluster.main.name}/${local.ecs_service_names_for_scaling[each.key]}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  depends_on = [terraform_data.availability_and_connection_budget]
}

resource "aws_appautoscaling_policy" "ecs_cpu" {
  for_each = local.scalable_services

  name               = "${var.name}-${each.key}-cpu-target"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs[each.key].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs[each.key].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs[each.key].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = var.service_cpu_target[each.key]
    scale_in_cooldown  = var.scale_in_cooldown_seconds
    scale_out_cooldown = var.scale_out_cooldown_seconds

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

resource "aws_appautoscaling_policy" "ecs_memory" {
  for_each = local.scalable_services

  name               = "${var.name}-${each.key}-memory-target"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs[each.key].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs[each.key].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs[each.key].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = var.service_memory_target[each.key]
    scale_in_cooldown  = var.scale_in_cooldown_seconds
    scale_out_cooldown = var.scale_out_cooldown_seconds

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
  }
}

resource "aws_appautoscaling_policy" "alb_requests" {
  for_each = local.public_services

  name               = "${var.name}-${each.key}-requests-target"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs[each.key].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs[each.key].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs[each.key].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = var.alb_requests_per_target[each.key]
    scale_in_cooldown  = var.scale_in_cooldown_seconds
    scale_out_cooldown = var.scale_out_cooldown_seconds

    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.service[each.key].arn_suffix}/${aws_lb_target_group.service[each.key].arn_suffix}"
    }
  }
}

resource "aws_appautoscaling_policy" "audit_queue_scale_out" {
  count = local.audit_sqs_enabled && var.enable_audit_consumer ? 1 : 0

  name               = "${var.name}-audit-queue-scale-out"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.ecs["audit_consumer"].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs["audit_consumer"].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs["audit_consumer"].service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = var.scale_out_cooldown_seconds
    metric_aggregation_type = "Maximum"

    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 1
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "audit_queue_scale_out" {
  count = local.audit_sqs_enabled && var.enable_audit_consumer ? 1 : 0

  alarm_name          = "${var.name}-audit-queue-scale-out"
  alarm_description   = "Scale the audit consumer when native SQS backlog exceeds the configured per-consumer threshold"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  period              = 60
  statistic           = "Maximum"
  threshold           = var.audit_sqs_scale_out_backlog
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_appautoscaling_policy.audit_queue_scale_out[0].arn]

  dimensions = { QueueName = aws_sqs_queue.audit[0].name }
  tags       = var.tags
}

resource "aws_db_parameter_group" "postgres" {
  name   = "${var.name}-postgres16"
  family = "postgres16"

  parameter {
    name         = "max_connections"
    value        = tostring(var.rds_max_connections)
    apply_method = "pending-reboot"
  }
  parameter {
    name  = "log_lock_waits"
    value = "1"
  }
  parameter {
    name  = "deadlock_timeout"
    value = "1000"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = tostring(var.rds_slow_query_milliseconds)
  }

  tags = var.tags
}

resource "aws_iam_role" "rds_enhanced_monitoring" {
  name = "${var.name}-rds-monitoring"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
