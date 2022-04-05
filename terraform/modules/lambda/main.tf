locals{
  lambda_dynamo_secrets_role = "arn:aws:iam::521089659248:role/Lambda-Dynamo-Secrets"

   lambdas = toset(["HighAnalytics", "HighGetAdmin", "HighBlackFriday", "HighVaccine", "HighPaypalReconciliation", "HighPayments", "HighLiveClassSignup"])
}

resource "null_resource" "build" {
  # Changes to any instance of the cluster requires re-provisioning
   for_each = local.lambdas
    triggers = {
      dependencies_versions = filemd5("${path.module}/${each.value}/python/requirements.txt")                  
     }

     provisioner "local-exec" {
       command = "pip install -r ${path.module}/${each.value}/python/requirements.txt -t ${path.module}/${each.value}/python/ --upgrade"
     }
  }

data archive_file "archive" {
  for_each = local.lambdas
    type = "zip"
    source_dir = "${path.module}/${each.value}/python/"
    output_path = "${path.module}/${each.value}/function.zip"

    depends_on = [null_resource.build]
}
   

resource "aws_lambda_function" "lambda" {
  for_each = local.lambdas
    filename      = "${data.archive_file.archive[each.value].output_path}"
    function_name = each.value
    role          = local.lambda_dynamo_secrets_role
    handler       = "lambda_function.lambda_handler"
    runtime       = "python3.8"
    timeout       = 10
    memory_size   = 1024

    source_code_hash = "${data.archive_file.archive[each.value].output_base64sha256}"

    environment {
      variables = {
        foo = "bar"
      }
    }
}

output "lambda_arns" {
  value = values( aws_lambda_function.lambda)[*].arn
  #value       = aws_lambda_function.lambda
}


