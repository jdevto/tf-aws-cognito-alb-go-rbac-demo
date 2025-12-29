variable "region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-southeast-2"
}

variable "name" {
  description = "Name of the resources"
  type        = string
  default     = "test"
}

variable "environment" {
  description = "Environment of the resources"
  type        = string
  default     = "dev"
}

variable "availability_zones" {
  description = "Availability zones for the resources"
  type        = list(string)
  default     = ["ap-southeast-2a", "ap-southeast-2b"]
}

variable "one_nat_gateway_per_az" {
  description = "Should be true if you want one NAT Gateway per availability zone. Otherwise, one NAT Gateway will be used for all AZs."
  type        = bool
  default     = false
}

variable "s3_enable_versioning" {
  description = "Enable versioning for the S3 bucket"
  type        = bool
  default     = true
}

variable "s3_force_destroy" {
  description = "Force destroy the S3 bucket"
  type        = bool
  default     = true
}

variable "admin_email" {
  description = "Email address(es) for admin users (has all permissions). Can be a string or list of strings. Empty string or empty list = no admin users."
  type        = any
  default     = null
}

variable "request_creator_email" {
  description = "Email address(es) for request creator users (can create requests and view all). Can be a string or list of strings. Empty string or empty list = no request creator users."
  type        = any
  default     = null
}

variable "reviewer_email" {
  description = "Email address(es) for reviewer users (can approve requests and view all). Can be a string or list of strings. Empty string or empty list = no reviewer users."
  type        = any
  default     = null
}

variable "viewer_email" {
  description = "Email address(es) for viewer users (read-only access). Can be a string or list of strings. Empty string or empty list = no viewer users."
  type        = any
  default     = null
}

variable "domain_name" {
  description = "Domain name"
  type        = string
}

variable "dynamodb_deletion_protection_enabled" {
  description = "Enable deletion protection for the DynamoDB table"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "debug_enabled" {
  description = "Enable debug logging in the Go application"
  type        = bool
  default     = false
}
