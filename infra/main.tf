# VPC Module
module "vpc" {
  source = "./modules/vpc"

  name                   = local.name
  availability_zones     = var.availability_zones
  one_nat_gateway_per_az = var.one_nat_gateway_per_az
  tags                   = local.common_tags
}

# S3 Module with app file uploads
module "s3-config" {
  source = "./modules/s3"

  name              = local.name
  enable_versioning = var.s3_enable_versioning
  force_destroy     = var.s3_force_destroy
  tags              = local.common_tags

  # Upload all app files individually to preserve directory structure
  upload_files = {
    source_dir   = "${path.module}/../app"
    file_pattern = "**/*"
    s3_prefix    = "app"
    content_types = {
      ".go"   = "text/x-go"
      ".mod"  = "text/plain"
      ".sum"  = "text/plain"
      ".html" = "text/html"
      ".svg"  = "image/svg+xml"
      ".ico"  = "image/x-icon"
    }
  }
}

# EC2 Module
module "ec2" {
  source = "./modules/ec2"

  name                       = local.name
  vpc_id                     = module.vpc.vpc_id
  subnet_id                  = module.vpc.private_subnet_ids[0]
  s3_bucket_id               = module.s3-config.bucket_id
  allowed_security_group_ids = [module.alb.security_group_id]
  debug_enabled              = var.debug_enabled
  cognito_user_pool_arn      = module.cognito.user_pool_arn
  cognito_user_pool_id       = module.cognito.user_pool_id
  dynamodb_table_name        = module.dynamodb.table_name
  dynamodb_table_arn         = module.dynamodb.table_arn

  tags = local.common_tags
}

# ALB Module (create first without Cognito)
module "alb" {
  source = "./modules/alb"

  name       = local.name
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.public_subnet_ids # ALB should be in public subnets

  # Target instance(s) to register
  target_instance_ids = [
    module.ec2.instance_id
  ]

  # Listener settings
  certificate_arn     = data.aws_acm_certificate.web.arn
  enable_cognito_auth = true

  # Cognito auth config
  cognito_user_pool_arn       = module.cognito.user_pool_arn
  cognito_user_pool_client_id = module.cognito.user_pool_client_id
  cognito_user_pool_domain    = module.cognito.user_pool_domain

  tags = local.common_tags
}

# Route53 Module
module "route53" {
  source = "./modules/route53"

  name         = local.name
  domain_name  = var.domain_name
  alb_dns_name = module.alb.alb_dns_name
  alb_zone_id  = module.alb.alb_zone_id
}

# DynamoDB Module
module "dynamodb" {
  source = "./modules/dynamodb"

  name                        = local.name
  deletion_protection_enabled = var.dynamodb_deletion_protection_enabled
  tags                        = local.common_tags
}

# Cognito Module
module "cognito" {
  source = "./modules/cognito"

  name          = local.name
  alb_dns_name  = module.alb.alb_dns_name
  custom_domain = module.route53.custom_domain

  user_groups = {
    admins = {
      description = "Administrators with full access to all features"
      precedence  = 0
    }
    request_creators = {
      description = "Users who can create requests and view all requests"
      precedence  = 1
    }
    reviewers = {
      description = "Users who can approve requests and view all requests"
      precedence  = 2
    }
    viewers = {
      description = "Users with read-only access to view all requests"
      precedence  = 3
    }
  }

  seed_users = local.seed_users

  tags = local.common_tags
}
