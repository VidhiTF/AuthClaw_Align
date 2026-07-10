provider "aws" {
  alias  = "primary"
  region = var.primary_region

  skip_credentials_validation = var.ci_skip_aws_validation
  skip_metadata_api_check     = var.ci_skip_aws_validation
  skip_requesting_account_id  = var.ci_skip_aws_validation
  skip_region_validation      = var.ci_skip_aws_validation
}

provider "aws" {
  alias  = "secondary"
  region = var.secondary_region

  skip_credentials_validation = var.ci_skip_aws_validation
  skip_metadata_api_check     = var.ci_skip_aws_validation
  skip_requesting_account_id  = var.ci_skip_aws_validation
  skip_region_validation      = var.ci_skip_aws_validation
}
