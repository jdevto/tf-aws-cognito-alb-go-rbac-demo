variable "name" {
  description = "Name of the resources"
  type        = string
}

variable "domain_name" {
  description = "Domain name"
  type        = string
}

variable "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  type        = string
}

variable "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  type        = string
}
