# Data source for random suffix
resource "random_id" "suffix" {
  byte_length = 3 # 3 bytes = 6 hex characters
}

# Data source for ACM certificate
data "aws_acm_certificate" "web" {
  domain   = "*.${var.domain_name}"
  statuses = ["ISSUED"]
}
