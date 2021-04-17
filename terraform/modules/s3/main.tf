module "aws_static_website" {
  source = "cloudmaniac/static-website/aws"

  website-domain-main     = "funfithappy.com"
  website-domain-redirect = "www.funfithappy.com"
}