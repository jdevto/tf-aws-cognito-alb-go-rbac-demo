output "custom_domain" {
  description = "Custom domain FQDN"
  value       = aws_route53_record.this.fqdn
}
