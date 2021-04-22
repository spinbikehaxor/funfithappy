resource "aws_secretsmanager_secret" "captcha_secret" {
  name = "captcha_secret"
  kms_key_id = var.kms_id
}


resource "aws_secretsmanager_secret" "jwt-secret" {
  name = "jwt-secret"
  kms_key_id = var.kms_id
}

resource "aws_secretsmanager_secret" "PaypalSecret" {
  name = "PaypalSecret"
  kms_key_id = var.kms_id
}

resource "aws_secretsmanager_secret" "pwd-reset-key" {
  name = "pwd-reset-key"
  kms_key_id = var.kms_id
}

