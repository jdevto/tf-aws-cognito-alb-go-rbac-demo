variable "name" {
  description = "Name of the project"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC where the EC2 instance will be deployed"
  type        = string
}

variable "subnet_id" {
  description = "ID of the subnet where the EC2 instance will be deployed"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for the service"
  type        = string
  default     = "t3.small"
}

variable "port" {
  description = "Port on which the service will listen"
  type        = number
  default     = 8080
}

variable "tags" {
  description = "A map of tags to assign to the resources"
  type        = map(string)
  default     = {}
}

variable "allowed_security_group_ids" {
  description = "List of security group IDs allowed to access the port. If provided, traffic from these security groups will be allowed."
  type        = list(string)
  default     = null
}

variable "allowed_cidr_blocks" {
  description = "List of CIDR blocks allowed to access the port. If provided, traffic from these CIDR blocks will be allowed."
  type        = list(string)
  default     = null
}

variable "additional_policy_arns" {
  description = "List of additional IAM policy ARNs to attach to the EC2 instance role"
  type        = list(string)
  default     = []
}

variable "additional_policy_statements" {
  description = "List of additional IAM policy statements to add as an inline policy. Each statement should be a map with Effect, Action, and Resource keys."
  type = list(object({
    Effect   = string
    Action   = list(string)
    Resource = list(string)
  }))
  default = []
}

variable "s3_bucket_id" {
  description = "ID of the S3 bucket to use for the service"
  type        = string
}

variable "debug_enabled" {
  description = "Enable debug logging in the Go application"
  type        = bool
  default     = false
}

variable "cognito_user_pool_arn" {
  description = "ARN of the Cognito user pool (for querying user groups)"
  type        = string
  default     = null
}

variable "cognito_user_pool_id" {
  description = "ID of the Cognito user pool (for querying user groups)"
  type        = string
  default     = null
}

variable "permission_groups" {
  description = "JSON string mapping permission names to groups. Example: '{\"create_request\":[\"request_creators\"],\"approve\":[\"reviewers\"],\"view\":[\"request_creators\",\"reviewers\",\"viewers\"]}'. If not set, uses defaults."
  type        = string
  default     = null
}

variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table for storing requests"
  type        = string
  default     = null
}

variable "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table for storing requests"
  type        = string
  default     = null
}
