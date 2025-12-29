# DynamoDB Table for Requests
resource "aws_dynamodb_table" "requests" {
  name                        = "${var.name}-requests"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "request_id"
  deletion_protection_enabled = var.deletion_protection_enabled

  attribute {
    name = "request_id"
    type = "S"
  }

  tags = merge(var.tags, {
    Name = "${var.name}-requests"
  })
}
