locals{
  lambda_dynamo_secrets_role = "arn:aws:iam::521089659248:role/Lambda-Dynamo-Secrets"

   lambdas = {
    "HighAnalytics"           = "python/HighAnalytics"
    }
}

resource "null_resource" "build" {
  # Changes to any instance of the cluster requires re-provisioning
   for_each = local.lambdas
    triggers = {
      dependencies_versions = filemd5("${path.module}/${each.key}/python/requirements.txt")                  
     }

     provisioner "local-exec" {
       command = "pip install -r ${path.module}/${each.key}/python/requirements.txt -t ${path.module}/${each.key}/python/ --upgrade"
     }
  }

data archive_file "archive" {
  for_each = local.lambdas
    type = "zip"
    source_dir = "${path.module}/${each.key}/python/"
    output_path = "${path.module}/${each.key}/function.zip"

    depends_on = [null_resource.build]
}
   

resource "aws_lambda_function" "lambda" {
  for_each = local.lambdas
    filename      = "${data.archive_file.archive[each.key].output_path}"
    function_name = each.key
    role          = local.lambda_dynamo_secrets_role
    handler       = "lambda_function.lambda_handler"
    runtime       = "python3.8"
    timeout       = 10
    memory_size   = 1024

    source_code_hash = "${data.archive_file.archive[each.key].output_base64sha256}"

    environment {
      variables = {
        foo = "bar"
      }
    }
}

