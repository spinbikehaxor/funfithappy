resource "aws_secretsmanager_secret" "captcha_secret" {
  name = "captcha_secret"
  kms_key_id = var.kms_id
}