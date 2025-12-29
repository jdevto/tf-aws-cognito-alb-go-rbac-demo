variable "name" {
  description = "Name prefix for ALB resources"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC where the ALB will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs where the ALB will be deployed"
  type        = list(string)
}

variable "target_instance_ids" {
  description = "List of target instance IDs to attach to the target group"
  type        = list(string)
  default     = []
}

variable "create_target_attachments" {
  description = "Whether to create target group attachments in this module"
  type        = bool
  default     = true
}

variable "target_port" {
  description = "Port on which the targets receive traffic"
  type        = number
  default     = 8080
}

variable "target_protocol" {
  description = "Protocol to use for routing traffic to the targets"
  type        = string
  default     = "HTTP"
}

variable "target_type" {
  description = "Type of targets (instance, ip, lambda, alb)"
  type        = string
  default     = "instance"
}

variable "deregistration_delay" {
  description = "Deregistration delay in seconds for targets"
  type        = number
  default     = 30
}

variable "internal" {
  description = "If true, the ALB will be internal"
  type        = bool
  default     = false
}

variable "enable_deletion_protection" {
  description = "If true, deletion of the load balancer will be disabled"
  type        = bool
  default     = false
}

variable "enable_http2" {
  description = "Enable HTTP/2 support on the ALB"
  type        = bool
  default     = true
}

variable "enable_http_listener" {
  description = "Enable HTTP listener (port http_listener_port)"
  type        = bool
  default     = true
}

variable "enable_https_listener" {
  description = "Enable HTTPS listener (port https_listener_port)"
  type        = bool
  default     = true
}

variable "http_listener_port" {
  description = "Port for HTTP listener and SG ingress"
  type        = number
  default     = 80
}

variable "https_listener_port" {
  description = "Port for HTTPS listener and SG ingress"
  type        = number
  default     = 443
}

variable "http_redirect_status_code" {
  description = "Status code for HTTP -> HTTPS redirect"
  type        = string
  default     = "HTTP_301"
}

variable "alb_ingress_cidrs" {
  description = "CIDR blocks allowed to access the ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "certificate_arn" {
  description = "ARN of the SSL certificate for HTTPS listener"
  type        = string
  default     = null
}

variable "ssl_policy" {
  description = "Name of the SSL Policy for the HTTPS listener"
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "enable_cognito_auth" {
  description = "Enable Cognito authentication on the HTTPS listener"
  type        = bool
  default     = false
}

variable "cognito_user_pool_arn" {
  description = "Cognito user pool ARN for authenticate-cognito"
  type        = string
  default     = null
}

variable "cognito_user_pool_client_id" {
  description = "Cognito user pool client ID for authenticate-cognito"
  type        = string
  default     = null
}

variable "cognito_user_pool_domain" {
  description = "Cognito user pool domain for authenticate-cognito"
  type        = string
  default     = null
}

variable "cognito_scope" {
  description = "Scope for Cognito authentication"
  type        = string
  default     = "openid email profile"
}

variable "cognito_session_cookie_name" {
  description = "Session cookie name for Cognito authentication"
  type        = string
  default     = "AWSELBAuthSessionCookie"
}

variable "cognito_session_timeout" {
  description = "Session timeout (seconds) for Cognito authentication"
  type        = number
  default     = 3600
}

variable "cognito_on_unauthenticated_request" {
  description = "Behavior on unauthenticated requests (authenticate, deny, allow)"
  type        = string
  default     = "authenticate"
}


variable "health_check_healthy_threshold" {
  description = "Number of consecutive health checks successes required before considering an unhealthy target healthy"
  type        = number
  default     = 2
}

variable "health_check_unhealthy_threshold" {
  description = "Number of consecutive health check failures required before considering a target unhealthy"
  type        = number
  default     = 2
}

variable "health_check_timeout" {
  description = "Amount of time, in seconds, during which no response means a failed health check"
  type        = number
  default     = 5
}

variable "health_check_interval" {
  description = "Approximate amount of time, in seconds, between health checks of an individual target"
  type        = number
  default     = 30
}

variable "health_check_path" {
  description = "Destination for the health check request"
  type        = string
  default     = "/health"
}

variable "health_check_protocol" {
  description = "Protocol to use to connect with the target"
  type        = string
  default     = "HTTP"
}

variable "health_check_matcher" {
  description = "HTTP codes to use when checking for a successful response from a target"
  type        = string
  default     = "200"
}

variable "tags" {
  description = "A map of tags to assign to the resources"
  type        = map(string)
  default     = {}
}
