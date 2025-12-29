# Get Route53 hosted zone
data "aws_route53_zone" "this" {
  name         = var.domain_name
  private_zone = false
}

# Route53 record
resource "aws_route53_record" "this" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = "${var.name}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
