
locals {
  lambdas = {
    "HighAnalytics"           = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighAnalytics/invocations"
    "HighBlackFriday"         = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighBlackFriday/invocations"
    "HighCancelClass"         = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighCancelClass/invocations"
    "HighCancelReservation"   = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighCancelReservation/invocations"
    "HighChangeClassLocation" = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighChangeClassLocation/invocations"
    "HighContactUs"           = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighContactUs/invocations"
    "HighContactUsMobile"     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighContactUsMobile/invocations"
    "HighCreateLiveClass"     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighCreateLiveClass/invocations"
    "HighCreditUser"          = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighCreditUser/invocations"
    "HighForgotPassword"      = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighForgotPassword/invocations"
    "HighGetAdmin"            = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighGetAdmin/invocations"
    "HighGetAllUsers"         = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighGetAllUsers/invocations"
    "HighGetUpcomingClasses"  = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighGetUpcomingClasses/invocations"
    "HighGetUser"             = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighGetUser/invocations"
    "HighLiveClassSignup"     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighLiveClassSignup/invocations"
    "HighLivePayment"         = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighLivePayment/invocations"
    "HighLogin"               = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighLogin/invocations"
    "HighRegistration"        = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighRegistration/invocations"
    "HighResetPassword"       = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighResetPassword/invocations"
    "HighWaiver"              = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:521089659248:function:HighWaiver/invocations"
  }
}


  # API Gateway
  resource "aws_api_gateway_rest_api" "api" {
    for_each = local.lambdas

      name = each.key

      endpoint_configuration {
        types = ["REGIONAL"]
    }
  }

resource "aws_api_gateway_resource" "resource" {
  for_each = local.lambdas
    parent_id   = aws_api_gateway_rest_api.api[each.key].root_resource_id
    rest_api_id = aws_api_gateway_rest_api.api[each.key].id
    path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "method" {
   for_each = local.lambdas
    rest_api_id   = aws_api_gateway_rest_api.api[each.key].id
    resource_id   = aws_api_gateway_resource.resource[each.key].id
    http_method   = "ANY"
    authorization = "NONE"
}

resource "aws_api_gateway_integration" "integration" {
  for_each =  local.lambdas
    rest_api_id             = aws_api_gateway_rest_api.api[each.key].id
    resource_id             = aws_api_gateway_resource.resource[each.key].id
    http_method             = aws_api_gateway_method.method[each.key].http_method
    integration_http_method = "ANY"
    type                    = "AWS_PROXY"
    uri                     = each.value
}


resource "aws_lambda_permission" "lambda_permission" {
  for_each =  local.lambdas
    statement_id  = "AllowLambdaInvocation"
    action        = "lambda:InvokeFunction"
    function_name = each.key
    principal     = "apigateway.amazonaws.com"

    # The /*/*/* part allows invocation from any stage, method and resource path
    # within API Gateway REST API.
    source_arn = "${aws_api_gateway_rest_api.api[each.key].execution_arn}/*/*/*"
}