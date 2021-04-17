resource "aws_dynamodb_table" "site-users" {
  name           = "SiteUsers"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "username"

  attribute {
    name = "username"
    type = "S"
  }

resource "aws_dynamodb_table" "high-waivers" {
  name           = "HighWaivers"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "username"

  attribute {
    name = "username"
    type = "S"
  }