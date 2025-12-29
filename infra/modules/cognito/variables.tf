variable "name" {
  type        = string
  description = "Name of the resources"
}

variable "alb_dns_name" {
  type        = string
  description = "ALB DNS name used for callback / logout URLs (no protocol)"
}

variable "custom_domain" {
  type        = string
  description = "Optional custom domain for callback URLs"
  default     = ""
}

variable "tags" {
  type        = map(string)
  description = "Common tags"
  default     = {}
}

# Password policy
variable "password_minimum_length" {
  type    = number
  default = 8
}

variable "password_require_lowercase" {
  type    = bool
  default = true
}

variable "password_require_uppercase" {
  type    = bool
  default = true
}

variable "password_require_numbers" {
  type    = bool
  default = true
}

variable "password_require_symbols" {
  type    = bool
  default = false
}

variable "temporary_password_validity_days" {
  type    = number
  default = 7
}

# OAuth / client
variable "allowed_oauth_flows" {
  type    = list(string)
  default = ["code"]
}

variable "allowed_oauth_scopes" {
  type    = list(string)
  default = ["openid", "email", "profile"]
}

variable "supported_identity_providers" {
  type    = list(string)
  default = ["COGNITO"]
}

variable "id_token_validity" {
  type    = number
  default = 60
}

variable "access_token_validity" {
  type    = number
  default = 60
}

variable "refresh_token_validity" {
  type    = number
  default = 30
}

variable "read_attributes" {
  type    = list(string)
  default = ["email", "email_verified"]
}

# Groups
variable "user_groups" {
  description = "Map of Cognito groups"
  type = map(object({
    description = string
    precedence  = number
  }))

  default = {
    admin = {
      description = "Admin users with full access"
      precedence  = 1
    }
    readonly = {
      description = "Read-only users with limited access"
      precedence  = 2
    }
  }
}

# Seed users
variable "seed_users" {
  description = "List of seed users to create and assign to groups"
  type = list(object({
    email      = string
    group_name = string
  }))
  default = []
}
