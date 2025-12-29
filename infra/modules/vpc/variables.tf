variable "name" {
  description = "Name of the VPC"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["ap-southeast-2a", "ap-southeast-2b"]
}

variable "one_nat_gateway_per_az" {
  description = "Should be true if you want one NAT Gateway per availability zone. Otherwise, one NAT Gateway will be used for all AZs."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
