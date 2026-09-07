locals {
  edge_service_origins = {
    api     = "backend"
    gateway = "gateway"
  }
  edge_service_domains = {
    api     = local.approved_public_domains.api
    gateway = local.approved_public_domains.gateway
  }
  caching_disabled_policy_id = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
  all_viewer_policy_id       = "216adef6-5c7f-47e4-b989-5492eafa07d3"
}

resource "terraform_data" "production_edge_required" {
  input = var.enable_public_edge

  lifecycle {
    precondition {
      condition     = !local.is_production || var.enable_public_edge
      error_message = "Production must enable the CloudFront/WAF edge; private ALB origins have no alternate public entry."
    }
  }
}

resource "terraform_data" "public_edge_guardrails" {
  count = var.enable_public_edge ? 1 : 0

  input = local.approved_public_domains

  lifecycle {
    precondition {
      condition     = contains(["staging", "production"], var.public_url_environment)
      error_message = "The public URL boundary must be staging or production."
    }
    precondition {
      condition     = var.primary_region == "us-east-1"
      error_message = "CloudFront, WAF, and the viewer certificate must be managed through the us-east-1 primary provider."
    }
    precondition {
      condition     = var.hosted_zone_id != ""
      error_message = "hosted_zone_id is required when enable_public_edge is true."
    }
    precondition {
      condition     = can(regex("^arn:aws[a-z-]*:acm:us-east-1:[0-9]{12}:certificate/", var.edge_certificate_arn))
      error_message = "edge_certificate_arn must be an ACM certificate ARN in us-east-1."
    }
    precondition {
      condition     = var.primary_certificate_arn != "" || var.certificate_arn != ""
      error_message = "A primary regional ACM certificate is required for TLS to the private ALB origins."
    }
    precondition {
      condition     = !var.enable_secondary || var.secondary_certificate_arn != "" || var.certificate_arn != ""
      error_message = "A secondary regional ACM certificate is required when secondary origins are enabled."
    }
    precondition {
      condition     = var.public_url_environment != "production" || length(var.edge_alarm_action_arns) > 0
      error_message = "Production requires at least one edge_alarm_action_arns destination."
    }
    precondition {
      condition     = var.public_url_environment != "production" || can(regex("^[0-9]{12}$", var.aws_account_id))
      error_message = "Production requires aws_account_id so log delivery can be scoped to the deployment account."
    }
  }
}

resource "random_id" "marketing_bucket" {
  count       = var.enable_public_edge ? 1 : 0
  byte_length = 4
}

resource "aws_s3_bucket" "marketing" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0

  bucket        = substr("${local.name}-marketing-${random_id.marketing_bucket[0].hex}", 0, 63)
  force_destroy = false
  tags          = merge(local.tags, { DataClass = "public-content" })
}

resource "aws_s3_bucket_versioning" "marketing" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0
  bucket   = aws_s3_bucket.marketing[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "marketing" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0
  bucket   = aws_s3_bucket.marketing[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "marketing" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0
  bucket   = aws_s3_bucket.marketing[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_cloudfront_origin_access_control" "marketing" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0

  name                              = "${local.name}-marketing-oac"
  description                       = "Signed access to the private AuthClaw marketing bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_vpc_origin" "primary" {
  provider = aws.primary
  for_each = var.enable_public_edge ? module.primary.origin_load_balancers : {}

  vpc_origin_endpoint_config {
    name                   = "${local.name}-primary-${each.key}"
    arn                    = each.value.arn
    http_port              = 80
    https_port             = 443
    origin_protocol_policy = "https-only"
    origin_ssl_protocols {
      items    = ["TLSv1.2"]
      quantity = 1
    }
  }

  depends_on = [terraform_data.public_edge_guardrails]
  tags       = local.tags
}

resource "aws_cloudfront_vpc_origin" "secondary" {
  provider = aws.primary
  for_each = var.enable_public_edge && var.enable_secondary ? module.secondary[0].origin_load_balancers : {}

  vpc_origin_endpoint_config {
    name                   = "${local.name}-secondary-${each.key}"
    arn                    = each.value.arn
    http_port              = 80
    https_port             = 443
    origin_protocol_policy = "https-only"
    origin_ssl_protocols {
      items    = ["TLSv1.2"]
      quantity = 1
    }
  }

  tags = local.tags
}

resource "aws_wafv2_web_acl" "edge" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0

  name  = "${local.name}-edge"
  scope = "CLOUDFRONT"
  default_action {
    allow {}
  }

  rule {
    name     = "aws-common-rules"
    priority = 10
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-common-rules"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 20
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-known-bad-inputs"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "per-ip-rate-limit"
    priority = 30
    action {
      block {}
    }
    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.waf_rate_limit
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-rate-limit"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-edge"
    sampled_requests_enabled   = false
  }
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "waf" {
  provider          = aws.primary
  count             = var.enable_public_edge ? 1 : 0
  name              = "aws-waf-logs-${local.name}-edge"
  retention_in_days = var.edge_log_retention_days
  tags              = merge(local.tags, { DataClass = "security-telemetry" })
}

resource "aws_wafv2_web_acl_logging_configuration" "edge" {
  provider                = aws.primary
  count                   = var.enable_public_edge ? 1 : 0
  resource_arn            = aws_wafv2_web_acl.edge[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  redacted_fields {
    single_header { name = "authorization" }
  }
  redacted_fields {
    single_header { name = "cookie" }
  }
  redacted_fields {
    query_string {}
  }
}

resource "aws_cloudfront_response_headers_policy" "security" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0
  name     = "${local.name}-security-headers"

  security_headers_config {
    content_type_options { override = true }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
  }

  dynamic "custom_headers_config" {
    for_each = var.public_url_environment == "staging" ? [1] : []
    content {
      items {
        header   = "X-Robots-Tag"
        value    = "noindex, nofollow"
        override = true
      }
    }
  }
}

resource "aws_cloudfront_distribution" "service" {
  provider = aws.primary
  for_each = var.enable_public_edge ? local.edge_service_origins : {}

  enabled         = true
  is_ipv6_enabled = true
  aliases         = [local.edge_service_domains[each.key]]
  comment         = "${local.name} ${each.key}; CloudFront/WAF is the only public entry"
  web_acl_id      = aws_wafv2_web_acl.edge[0].arn
  price_class     = "PriceClass_100"
  http_version    = "http2and3"

  origin {
    domain_name = module.primary.origin_load_balancers[each.value].dns_name
    origin_id   = "${each.key}-primary"
    vpc_origin_config { vpc_origin_id = aws_cloudfront_vpc_origin.primary[each.value].id }
  }

  dynamic "origin" {
    for_each = var.enable_secondary ? [1] : []
    content {
      domain_name = module.secondary[0].origin_load_balancers[each.value].dns_name
      origin_id   = "${each.key}-secondary"
      vpc_origin_config { vpc_origin_id = aws_cloudfront_vpc_origin.secondary[each.value].id }
    }
  }

  dynamic "origin_group" {
    for_each = var.enable_secondary ? [1] : []
    content {
      origin_id = "${each.key}-regional-failover"
      failover_criteria { status_codes = [500, 502, 503, 504] }
      member { origin_id = "${each.key}-primary" }
      member { origin_id = "${each.key}-secondary" }
    }
  }

  default_cache_behavior {
    target_origin_id           = var.enable_secondary ? "${each.key}-regional-failover" : "${each.key}-primary"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = local.caching_disabled_policy_id
    origin_request_policy_id   = local.all_viewer_policy_id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
    compress                   = true
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }
  viewer_certificate {
    acm_certificate_arn      = var.edge_certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }
  tags = local.tags
}

resource "aws_cloudfront_distribution" "console" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0

  enabled         = true
  is_ipv6_enabled = true
  aliases         = [local.approved_public_domains.console]
  comment         = "${local.name} console; CloudFront/WAF is the only public entry"
  web_acl_id      = aws_wafv2_web_acl.edge[0].arn
  price_class     = "PriceClass_100"
  http_version    = "http2and3"

  origin {
    domain_name = module.primary.origin_load_balancers["console"].dns_name
    origin_id   = "console-primary"
    vpc_origin_config { vpc_origin_id = aws_cloudfront_vpc_origin.primary["console"].id }
  }
  dynamic "origin" {
    for_each = var.public_url_environment == "staging" ? [1] : []
    content {
      domain_name              = aws_s3_bucket.marketing[0].bucket_regional_domain_name
      origin_id                = "marketing"
      origin_access_control_id = aws_cloudfront_origin_access_control.marketing[0].id
    }
  }
  dynamic "origin" {
    for_each = var.public_url_environment == "staging" ? [1] : []
    content {
      domain_name = module.primary.origin_load_balancers["backend"].dns_name
      origin_id   = "intake-primary"
      vpc_origin_config { vpc_origin_id = aws_cloudfront_vpc_origin.primary["backend"].id }
    }
  }

  dynamic "origin" {
    for_each = var.enable_secondary ? [1] : []
    content {
      domain_name = module.secondary[0].origin_load_balancers["console"].dns_name
      origin_id   = "console-secondary"
      vpc_origin_config { vpc_origin_id = aws_cloudfront_vpc_origin.secondary["console"].id }
    }
  }
  dynamic "origin" {
    for_each = var.enable_secondary && var.public_url_environment == "staging" ? [1] : []
    content {
      domain_name = module.secondary[0].origin_load_balancers["backend"].dns_name
      origin_id   = "intake-secondary"
      vpc_origin_config { vpc_origin_id = aws_cloudfront_vpc_origin.secondary["backend"].id }
    }
  }
  dynamic "origin_group" {
    for_each = var.enable_secondary ? [1] : []
    content {
      origin_id = "console-regional-failover"
      failover_criteria { status_codes = [500, 502, 503, 504] }
      member { origin_id = "console-primary" }
      member { origin_id = "console-secondary" }
    }
  }
  dynamic "origin_group" {
    for_each = var.enable_secondary && var.public_url_environment == "staging" ? [1] : []
    content {
      origin_id = "intake-regional-failover"
      failover_criteria { status_codes = [500, 502, 503, 504] }
      member { origin_id = "intake-primary" }
      member { origin_id = "intake-secondary" }
    }
  }

  default_cache_behavior {
    target_origin_id           = var.enable_secondary ? "console-regional-failover" : "console-primary"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = local.caching_disabled_policy_id
    origin_request_policy_id   = local.all_viewer_policy_id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
    compress                   = true
  }

  dynamic "ordered_cache_behavior" {
    for_each = var.public_url_environment == "staging" ? [1] : []
    content {
      path_pattern               = "/api/public/v1/access-requests*"
      target_origin_id           = var.enable_secondary ? "intake-regional-failover" : "intake-primary"
      viewer_protocol_policy     = "redirect-to-https"
      allowed_methods            = ["GET", "HEAD", "OPTIONS", "POST"]
      cached_methods             = ["GET", "HEAD"]
      cache_policy_id            = local.caching_disabled_policy_id
      origin_request_policy_id   = local.all_viewer_policy_id
      response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
      compress                   = true
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = var.public_url_environment == "staging" ? toset(["/", "/demo*", "/early-access*", "/marketing/*"]) : []
    content {
      path_pattern               = ordered_cache_behavior.value
      target_origin_id           = "marketing"
      viewer_protocol_policy     = "redirect-to-https"
      allowed_methods            = ["GET", "HEAD", "OPTIONS"]
      cached_methods             = ["GET", "HEAD"]
      cache_policy_id            = local.caching_disabled_policy_id
      response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
      compress                   = true
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }
  viewer_certificate {
    acm_certificate_arn      = var.edge_certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }
  tags = local.tags
}

resource "aws_cloudfront_function" "www_redirect" {
  provider = aws.primary
  count    = var.enable_public_edge && var.public_url_environment == "production" ? 1 : 0
  name     = "${local.name}-www-redirect"
  runtime  = "cloudfront-js-2.0"
  publish  = true
  code     = <<-EOT
    function handler(event) {
      var request = event.request;
      if (request.headers.host && request.headers.host.value === 'www.authclaw.ai') {
        var query = Object.keys(request.querystring).map(function (key) {
          return encodeURIComponent(key) + '=' + encodeURIComponent(request.querystring[key].value);
        }).join('&');
        return { statusCode: 301, statusDescription: 'Moved Permanently', headers: {
          location: { value: 'https://authclaw.ai' + request.uri + (query ? '?' + query : '') },
          'cache-control': { value: 'public, max-age=3600' }
        }};
      }
      return request;
    }
  EOT
}

resource "aws_cloudfront_distribution" "marketing" {
  provider = aws.primary
  count    = var.enable_public_edge && var.public_url_environment == "production" ? 1 : 0

  enabled             = true
  is_ipv6_enabled     = true
  aliases             = [local.approved_public_domains.marketing, local.approved_public_domains.www]
  default_root_object = "index.html"
  comment             = "${local.name} production marketing only"
  web_acl_id          = aws_wafv2_web_acl.edge[0].arn
  price_class         = "PriceClass_100"
  http_version        = "http2and3"

  origin {
    domain_name              = aws_s3_bucket.marketing[0].bucket_regional_domain_name
    origin_id                = "marketing"
    origin_access_control_id = aws_cloudfront_origin_access_control.marketing[0].id
  }
  origin {
    domain_name = module.primary.origin_load_balancers["backend"].dns_name
    origin_id   = "intake-primary"
    vpc_origin_config { vpc_origin_id = aws_cloudfront_vpc_origin.primary["backend"].id }
  }
  dynamic "origin" {
    for_each = var.enable_secondary ? [1] : []
    content {
      domain_name = module.secondary[0].origin_load_balancers["backend"].dns_name
      origin_id   = "intake-secondary"
      vpc_origin_config { vpc_origin_id = aws_cloudfront_vpc_origin.secondary["backend"].id }
    }
  }
  dynamic "origin_group" {
    for_each = var.enable_secondary ? [1] : []
    content {
      origin_id = "intake-regional-failover"
      failover_criteria { status_codes = [500, 502, 503, 504] }
      member { origin_id = "intake-primary" }
      member { origin_id = "intake-secondary" }
    }
  }

  default_cache_behavior {
    target_origin_id           = "marketing"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = local.caching_disabled_policy_id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
    compress                   = true
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.www_redirect[0].arn
    }
  }
  ordered_cache_behavior {
    path_pattern               = "/api/public/v1/access-requests*"
    target_origin_id           = var.enable_secondary ? "intake-regional-failover" : "intake-primary"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS", "POST"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = local.caching_disabled_policy_id
    origin_request_policy_id   = local.all_viewer_policy_id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
    compress                   = true
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.www_redirect[0].arn
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }
  viewer_certificate {
    acm_certificate_arn      = var.edge_certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }
  tags = local.tags
}

data "aws_iam_policy_document" "marketing" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.marketing[0].arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = var.public_url_environment == "production" ? [aws_cloudfront_distribution.marketing[0].arn] : [aws_cloudfront_distribution.console[0].arn]
    }
  }
}

resource "aws_s3_bucket_policy" "marketing" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0
  bucket   = aws_s3_bucket.marketing[0].id
  policy   = data.aws_iam_policy_document.marketing[0].json
}

locals {
  edge_dns_targets = var.enable_public_edge ? merge(
    {
      console = {
        name   = local.approved_public_domains.console
        domain = aws_cloudfront_distribution.console[0].domain_name
        zone   = aws_cloudfront_distribution.console[0].hosted_zone_id
      }
    },
    { for key, distribution in aws_cloudfront_distribution.service : key => {
      name   = local.edge_service_domains[key]
      domain = distribution.domain_name
      zone   = distribution.hosted_zone_id
    } },
    var.public_url_environment == "production" ? {
      marketing = {
        name   = local.approved_public_domains.marketing
        domain = aws_cloudfront_distribution.marketing[0].domain_name
        zone   = aws_cloudfront_distribution.marketing[0].hosted_zone_id
      }
      www = {
        name   = local.approved_public_domains.www
        domain = aws_cloudfront_distribution.marketing[0].domain_name
        zone   = aws_cloudfront_distribution.marketing[0].hosted_zone_id
      }
    } : {}
  ) : {}
}

resource "aws_route53_record" "edge" {
  provider = aws.primary
  for_each = local.edge_dns_targets
  zone_id  = var.hosted_zone_id
  name     = each.value.name
  type     = "A"
  alias {
    name                   = each.value.domain
    zone_id                = each.value.zone
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "edge_ipv6" {
  provider = aws.primary
  for_each = local.edge_dns_targets
  zone_id  = var.hosted_zone_id
  name     = each.value.name
  type     = "AAAA"
  alias {
    name                   = each.value.domain
    zone_id                = each.value.zone
    evaluate_target_health = false
  }
}

locals {
  edge_distribution_arns = var.enable_public_edge ? merge(
    { console = aws_cloudfront_distribution.console[0].arn },
    { for key, distribution in aws_cloudfront_distribution.service : key => distribution.arn },
    var.public_url_environment == "production" ? { marketing = aws_cloudfront_distribution.marketing[0].arn } : {}
  ) : {}
}

resource "aws_cloudwatch_metric_alarm" "cloudfront_5xx" {
  provider = aws.primary
  for_each = local.edge_distribution_arns

  alarm_name          = "${local.name}-${each.key}-cloudfront-5xx"
  namespace           = "AWS/CloudFront"
  metric_name         = "5xxErrorRate"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  dimensions = {
    DistributionId = split("/", each.value)[1]
    Region         = "Global"
  }
  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "waf_blocked" {
  provider = aws.primary
  count    = var.enable_public_edge ? 1 : 0

  alarm_name          = "${local.name}-waf-blocked-requests"
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns
  dimensions = {
    WebACL = aws_wafv2_web_acl.edge[0].name
    Region = "Global"
    Rule   = "ALL"
  }
  tags = local.tags
}
