output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.ec2.id
}

output "instance_private_ip" {
  description = "Private IP address of the EC2 instance"
  value       = aws_instance.ec2.private_ip
}

output "security_group_id" {
  description = "ID of the security group for the EC2 instance"
  value       = aws_security_group.ec2.id
}
