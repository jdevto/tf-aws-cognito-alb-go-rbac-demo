########################################
# Data Sources
########################################

data "aws_region" "current" {}

########################################
# Locals
########################################

locals {
  # Map seed users by email for stable for_each keys
  seed_users_by_email = {
    for u in var.seed_users : u.email => u
  }
}

########################################
# Cognito User Pool
########################################

resource "aws_cognito_user_pool" "this" {
  name = "${var.name}-pool"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length                   = var.password_minimum_length
    require_lowercase                = var.password_require_lowercase
    require_uppercase                = var.password_require_uppercase
    require_numbers                  = var.password_require_numbers
    require_symbols                  = var.password_require_symbols
    temporary_password_validity_days = var.temporary_password_validity_days
  }

  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = merge(
    {
      Name = "${var.name}-pool"
    },
    var.tags
  )
}

########################################
# Cognito User Pool Domain
########################################

resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.name
  user_pool_id = aws_cognito_user_pool.this.id
}

########################################
# Cognito User Pool Client
########################################

resource "aws_cognito_user_pool_client" "this" {
  name         = "${var.name}-client"
  user_pool_id = aws_cognito_user_pool.this.id

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = var.allowed_oauth_flows
  allowed_oauth_scopes                 = var.allowed_oauth_scopes
  supported_identity_providers         = var.supported_identity_providers

  callback_urls = concat(
    [
      "https://${var.alb_dns_name}/oauth2/idpresponse"
    ],
    var.custom_domain != "" ? [
      "https://${var.custom_domain}/oauth2/idpresponse"
    ] : []
  )

  logout_urls = concat(
    [
      "https://${var.alb_dns_name}"
    ],
    var.custom_domain != "" ? [
      "https://${var.custom_domain}"
    ] : []
  )

  id_token_validity      = var.id_token_validity
  access_token_validity  = var.access_token_validity
  refresh_token_validity = var.refresh_token_validity

  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "days"
  }

  generate_secret = true # Required for ALB Cognito authentication

  read_attributes = var.read_attributes

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]
}

########################################
# Cognito User Groups (modular)
########################################

resource "aws_cognito_user_group" "this" {
  for_each = var.user_groups

  name         = each.key
  user_pool_id = aws_cognito_user_pool.this.id
  description  = each.value.description
  precedence   = each.value.precedence
}

########################################
# Seed Users (modular)
########################################

# Generate random password for each seed user
# Ensure password meets Cognito policy requirements with minimum character counts
resource "random_password" "seed_user_password" {
  for_each = local.seed_users_by_email

  length      = max(16, var.password_minimum_length)
  special     = var.password_require_symbols
  upper       = var.password_require_uppercase
  lower       = var.password_require_lowercase
  numeric     = var.password_require_numbers
  min_special = var.password_require_symbols ? 1 : 0
  min_upper   = var.password_require_uppercase ? 1 : 0
  min_lower   = var.password_require_lowercase ? 1 : 0
  min_numeric = var.password_require_numbers ? 1 : 0

  # Exclude ambiguous characters
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_cognito_user" "seed" {
  for_each = local.seed_users_by_email

  user_pool_id = aws_cognito_user_pool.this.id
  username     = each.value.email

  attributes = {
    email          = each.value.email
    email_verified = true
  }

  temporary_password = random_password.seed_user_password[each.key].result

  lifecycle {
    ignore_changes = [
      temporary_password
    ]
  }
}

resource "aws_cognito_user_in_group" "seed" {
  for_each = aws_cognito_user.seed

  user_pool_id = aws_cognito_user_pool.this.id
  group_name   = local.seed_users_by_email[each.key].group_name
  username     = each.value.username
}
