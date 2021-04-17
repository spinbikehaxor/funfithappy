

resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Encrypt",
	      "kms:Decrypt",
	      "kms:ReEncrypt*",
	      "kms:GenerateDataKey*",
	      "kms:DescribeKey"
        ]
        Effect   = "Allow",
        Resource = aws_kms_key.key.arn
      }
    ]
  })
}

resource "aws_kms_key" "key" {
  description  = "CMK for db"
}

resource "aws_iam_role" "a" {
  name = "iam-role-for-grant"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
        "Principal": {
            "AWS": [
                "arn:aws:iam::521089659248:role/Lambda-Dynamo-Secrets",
                "arn:aws:iam::521089659248:user/wonton"
            ]
        },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "temp" {
  role       = "${aws_iam_role.a.name}"
  policy_arn = "${aws_iam_policy.policy.arn}"
}

resource "aws_kms_grant" "a" {
  name              = "my-grant"
  key_id            = aws_kms_key.key.key_id
  grantee_principal = aws_iam_role.a.arn
  operations        = ["Encrypt", "Decrypt", "GenerateDataKey"]
}

output "kms_id" {
  value = aws_kms_key.key.key_id
}

output "kms_arn" {
  value = aws_kms_key.key.arn
}