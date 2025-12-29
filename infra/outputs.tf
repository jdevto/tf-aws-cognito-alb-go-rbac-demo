output "admin_user_emails" {
  description = "Admin user email(s) (has all permissions). Can be string or list."
  value       = var.admin_email
}

output "request_creator_user_emails" {
  description = "Request creator user email(s) (can create requests and view all). Can be string or list."
  value       = var.request_creator_email
}

output "reviewer_user_emails" {
  description = "Reviewer user email(s) (can approve requests and view all). Can be string or list."
  value       = var.reviewer_email
}

output "viewer_user_emails" {
  description = "Viewer user email(s) (read-only access). Can be string or list."
  value       = var.viewer_email
}

output "custom_domain" {
  description = "Cognito custom domain URL"
  value       = "https://${module.route53.custom_domain}"
}

output "ssm_connect_command" {
  description = "Command to connect to the backend instance via SSM Session Manager"
  value       = "aws ssm start-session --region ${var.region} --target ${module.ec2.instance_id}"
}
