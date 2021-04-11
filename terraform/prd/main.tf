provider "aws" {
	region = "us-east-2"
}

module "api-gateway" {
	source = "../modules/api-gateway"
}