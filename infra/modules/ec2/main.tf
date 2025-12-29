# =============================================================================
# IAM ROLE FOR EC2 INSTANCE (SSM ACCESS)
# =============================================================================

# Data source to get current AWS account ID
data "aws_caller_identity" "current" {}

# Data source to get current AWS region
data "aws_region" "current" {}

# IAM role for EC2 instance
resource "aws_iam_role" "ec2" {
  name = "${var.name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.name}-ec2-role"
  })
}

# Attach SSM managed policy
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Attach AWS managed policy for CloudWatch logs
resource "aws_iam_role_policy_attachment" "ec2_cloudwatch" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Attach policy for S3 read access
resource "aws_iam_role_policy" "ec2_s3_read" {
  name = "${var.name}-ec2-s3-read-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ListAllBuckets"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3GetBucketMetadata"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning"
        ]
        Resource = "arn:aws:s3:::${var.s3_bucket_id}"
      },
      {
        Sid    = "S3GetObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "arn:aws:s3:::${var.s3_bucket_id}/*"
      }
    ]
  })
}

# Attach additional managed policies
resource "aws_iam_role_policy_attachment" "additional" {
  count      = length(var.additional_policy_arns)
  role       = aws_iam_role.ec2.name
  policy_arn = var.additional_policy_arns[count.index]
}

# Attach additional inline policy with custom statements
resource "aws_iam_role_policy" "additional" {
  count = length(var.additional_policy_statements) > 0 ? 1 : 0
  name  = "${var.name}-ec2-additional-policy"
  role  = aws_iam_role.ec2.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = var.additional_policy_statements
  })
}

# Policy for Cognito API access (to query user groups)
resource "aws_iam_role_policy" "ec2_cognito" {
  name = "${var.name}-ec2-cognito-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cognito-idp:AdminListGroupsForUser",
          "cognito-idp:AdminGetUser"
        ]
        Resource = var.cognito_user_pool_arn
      }
    ]
  })
}

# Policy for DynamoDB access
resource "aws_iam_role_policy" "ec2_dynamodb" {
  name = "${var.name}-ec2-dynamodb-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Scan",
          "dynamodb:Query"
        ]
        Resource = var.dynamodb_table_arn
      }
    ]
  })
}

# IAM instance profile
resource "aws_iam_instance_profile" "ec2" {
  name = "${var.name}-ec2-profile"
  role = aws_iam_role.ec2.name

  tags = merge(var.tags, {
    Name = "${var.name}-ec2-profile"
  })
}

# =============================================================================
# SECURITY GROUPS
# =============================================================================

# Security group for EC2 instance
resource "aws_security_group" "ec2" {
  name        = "${var.name}-ec2-sg"
  description = "Security group for EC2 instance"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.allowed_security_group_ids != null ? [1] : []
    content {
      description     = "Allowed security groups"
      from_port       = var.port
      to_port         = var.port
      protocol        = "tcp"
      security_groups = var.allowed_security_group_ids
    }
  }

  dynamic "ingress" {
    for_each = var.allowed_cidr_blocks != null ? [1] : []
    content {
      description = "Allowed CIDR blocks"
      from_port   = var.port
      to_port     = var.port
      protocol    = "tcp"
      cidr_blocks = var.allowed_cidr_blocks
    }
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-ec2-sg"
  })
}

# =============================================================================
# AMAZON LINUX 2023 AMI DATA SOURCE
# =============================================================================

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# EC2 instance
resource "aws_instance" "ec2" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = var.instance_type
  subnet_id     = var.subnet_id

  iam_instance_profile   = aws_iam_instance_profile.ec2.name
  vpc_security_group_ids = [aws_security_group.ec2.id]

  user_data_base64 = base64encode(templatefile("${path.module}/user_data.sh", {
    aws_region            = data.aws_region.current.region
    s3_bucket_id          = var.s3_bucket_id
    debug_enabled         = var.debug_enabled ? "true" : "false"
    cognito_user_pool_id  = var.cognito_user_pool_id != null ? var.cognito_user_pool_id : ""
    permission_groups     = var.permission_groups != null ? var.permission_groups : ""
    permission_groups_env = var.permission_groups != null ? "Environment=\"PERMISSION_GROUPS=${var.permission_groups}\"" : ""
    dynamodb_table_name   = var.dynamodb_table_name != null ? var.dynamodb_table_name : ""
  }))

  user_data_replace_on_change = true

  tags = merge(var.tags, {
    Name = "${var.name}-ec2"
  })
}
