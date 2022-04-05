provider "aws" {
	region = "us-east-2"
}

module "api-gateway" {
	source = "../modules/api-gateway"
}

module "dynamodb" {
	source = "../modules/dynamodb"
	kms_id = module.kms.kms_arn
}

module "s3" {
	source = "../modules/s3"
}

module "kms" {
	source = "../modules/kms"
}

module "secrets" {
	source = "../modules/secrets"
	kms_id = module.kms.kms_id
}

module "lambda" {
	source = "../modules/lambda"
	kms_id = module.kms.kms_id
}

module "cloudwatch" {
	source = "../modules/cloudwatch"
}

output "lambda_arns" {
  value = module.lambda.lambda_arns
 }