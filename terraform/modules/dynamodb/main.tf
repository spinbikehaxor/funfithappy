resource "aws_dynamodb_table" "site_users" {
  name           = "SiteUsers"
  billing_mode   = "PROVISIONED"
  
  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "username"

  attribute {
    name = "username"
    type = "S"
  }
}

resource "aws_dynamodb_table" "high_waiver" {
  name           = "HighWaiver"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "username"
  range_key		 = "email"
  
  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "username"
    type = "S"
  }
  attribute {
    name = "email"
    type = "S"
  }
}

resource "aws_dynamodb_table" "high_video_link" {
  name           = "HighVideoLink"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "classname"
  
  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "classname"
    type = "S"
  }
}

resource "aws_dynamodb_table" "high_streaming_times" {
  name           = "HighStreamingTimes"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "day_of_week"
  range_key		 = "time_of_day"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "day_of_week"
    type = "S"
  }
  attribute {
    name = "time_of_day"
    type = "S"
  }
}


resource "aws_dynamodb_table" "high_stream_stats" {
  name           = "HighStreamStats"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "date"
  range_key		 = "username"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "date"
    type = "S"
  }
  attribute {
    name = "username"
    type = "S"
  }

  global_secondary_index {
    name               = "username-index"
    hash_key           = "username"
    write_capacity     = 1
    read_capacity      = 1
    projection_type    = "ALL"
  }
}

resource "aws_dynamodb_table" "high_promo_credit" {
  name           = "HighPromoCredit"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "username"
  range_key      = "transaction-date"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "username"
    type = "S"
  }
  attribute {
    name = "transaction-date"
    type = "S"
  }
}

resource "aws_dynamodb_table" "high_promo" {
  name           = "HighPromo"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "promo_id"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "promo_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "high_payment" {
  name           = "HighPayment"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "username"
  range_key      = "transaction-date"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "username"
    type = "S"
  }
  attribute {
    name = "transaction-date"
    type = "S"
  }
}

resource "aws_dynamodb_table" "high_location" {
  name           = "HighLocation"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "name"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "name"
    type = "S"
  }
}

resource "aws_dynamodb_table" "high_live_payment" {
  name           = "HighLivePayment"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "username"
  range_key		 = "paypal_order_id"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "username"
    type = "S"
  }
   attribute {
    name = "paypal_order_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "high_live_credits" {
  name           = "HighLiveCredits"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "username"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "username"
    type = "S"
  }
}


resource "aws_dynamodb_table" "high_live_class_signup" {
  name           = "HighLiveClassSignup"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "class_date"
  range_key		 = "username"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "class_date"
    type = "S"
  }
  attribute {
    name = "username"
    type = "S"
  }

  global_secondary_index {
    name               = "username-index"
    hash_key           = "username"
    write_capacity     = 1
    read_capacity      = 1
    projection_type    = "ALL"
  }
}

resource "aws_dynamodb_table" "high_classes" {
  name           = "HighClasses"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "class_year"
  range_key		 = "class_date"

  server_side_encryption {
    enabled = true
    kms_key_arn = var.kms_id
  }

  attribute {
    name = "class_year"
    type = "S"
  }
  attribute {
    name = "class_date"
    type = "S"
  }
}

