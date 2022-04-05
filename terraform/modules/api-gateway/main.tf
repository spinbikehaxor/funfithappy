data "aws_caller_identity" "current" {}
data "aws_region" "current" {}


locals {
  lambdas = {
    "HighAnalytics"           = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighAnalytics/invocations"
    "HighBlackFriday"         = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighBlackFriday/invocations"
    "HighCancelClass"         = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighCancelClass/invocations"
    "HighCancelReservation"   = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighCancelReservation/invocations"
    "HighChangeClassLocation" = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighChangeClassLocation/invocations"
    "HighContactUs"           = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighContactUs/invocations"
    "HighContactUsMobile"     = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighContactUsMobile/invocations"
    "HighCreateLiveClass"     = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighCreateLiveClass/invocations"
    "HighCreditUser"          = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighCreditUser/invocations"
    "HighForgotPassword"      = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighForgotPassword/invocations"
    "HighGetAdmin"            = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighGetAdmin/invocations"
    "HighGetAllUsers"         = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighGetAllUsers/invocations"
    "HighGetUpcomingClasses"  = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighGetUpcomingClasses/invocations"
    "HighGetUser"             = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighGetUser/invocations"
    "HighLiveClassSignup"     = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighLiveClassSignup/invocations"
    "HighLivePayment"         = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighLivePayment/invocations"
    "HighLogin"               = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighLogin/invocations"
    "HighRegistration"        = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighRegistration/invocations"
    "HighResetPassword"       = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighResetPassword/invocations"
    "HighWaiver"              = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighWaiver/invocations"
    "HighChangeClassTime"     = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighChangeClassTime/invocations"
    "HighMessageParticipants" = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighMessageParticipants/invocations"
    "HighCreateLocation"      = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighCreateLocation/invocations"
    "HighPayments"             = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighPayments/invocations"
  }
}

#module "apigateway_with_cors" {
# source  = "alparius/apigateway-with-cors/aws"
#  version = "0.3.1"

#  for_each = local.lambdas
#   lambda_function_name = each.key
#    lambda_invoke_arn    = each.value 
#    http_method = "ANY"
#}


# ------------------------------------------------------------------
# the API Gateway and the main method
# ------------------------------------------------------------------

### the gateway itself
resource "aws_api_gateway_rest_api" "apigateway" {
  for_each = local.lambdas
      name        = each.key
      description = "rest api"
}


### permission to invoke lambdas
resource "aws_lambda_permission" "apigw_access_lambda" {
  for_each = local.lambdas
      statement_id  = "AllowAPIGatewayInvoke"
      action        = "lambda:InvokeFunction"
      function_name = each.key
      principal     = "apigateway.amazonaws.com"

      # The "/*/*" portion grants access from any method on any resource within the API Gateway REST API.
      source_arn = "${aws_api_gateway_rest_api.apigateway[each.key].execution_arn}/*/*/*"
}


### api route
resource "aws_api_gateway_resource" "proxy" {
  for_each = local.lambdas
      rest_api_id = aws_api_gateway_rest_api.apigateway[each.key].id
      parent_id   = aws_api_gateway_rest_api.apigateway[each.key].root_resource_id
      path_part   = "{proxy+}"
}


### connecting the api gateway with the internet
resource "aws_api_gateway_method" "main_method" {
  for_each = local.lambdas
      rest_api_id   = aws_api_gateway_rest_api.apigateway[each.key].id
      resource_id   = aws_api_gateway_resource.proxy[each.key].id
      http_method   = "ANY"
      authorization = "NONE"
}


### connecting the api gateway with the lambda
resource "aws_api_gateway_integration" "method_integration" {
  for_each = local.lambdas
      rest_api_id = aws_api_gateway_rest_api.apigateway[each.key].id
      resource_id = aws_api_gateway_method.main_method[each.key].resource_id
      http_method = aws_api_gateway_method.main_method[each.key].http_method

      integration_http_method = "ANY"
      type                    = "AWS_PROXY"
      uri                     = each.value

      #depends_on = aws_api_gateway_method[each.key].main_method
}


# ------------------------------------------------------------------
# enabling CORS by adding an OPTIONS method
# ------------------------------------------------------------------

resource "aws_api_gateway_method" "options_method" {
  for_each = local.lambdas
      rest_api_id   = aws_api_gateway_rest_api.apigateway[each.key].id
      resource_id   = aws_api_gateway_resource.proxy[each.key].id
      http_method   = "OPTIONS"
      authorization = "NONE"
}


resource "aws_api_gateway_method_response" "options_response" {
  for_each = local.lambdas
      rest_api_id = aws_api_gateway_rest_api.apigateway[each.key].id
      resource_id = aws_api_gateway_resource.proxy[each.key].id
      http_method = aws_api_gateway_method.options_method[each.key].http_method
      status_code = "200"

      response_models = {
        "application/json" = "Empty"
        }

      response_parameters = {
        "method.response.header.Access-Control-Allow-Headers" = true
        "method.response.header.Access-Control-Allow-Methods" = true
        "method.response.header.Access-Control-Allow-Origin"  = true
      }

        #depends_on = [aws_api_gateway_method.options_method]
}


resource "aws_api_gateway_integration" "options_integration" {
  for_each = local.lambdas
      rest_api_id = aws_api_gateway_rest_api.apigateway[each.key].id
      resource_id = aws_api_gateway_resource.proxy[each.key].id
      http_method = aws_api_gateway_method.options_method[each.key].http_method
      type        = "MOCK"

      request_templates = {
        "application/json" = "{ \"statusCode\": 200 }"
      }

      #depends_on = [aws_api_gateway_method[each.key].options_method]
}


resource "aws_api_gateway_integration_response" "options_integration_response" {
  for_each = local.lambdas
      rest_api_id = aws_api_gateway_rest_api.apigateway[each.key].id
      resource_id = aws_api_gateway_resource.proxy[each.key].id
      http_method = aws_api_gateway_method.options_method[each.key].http_method
      status_code = "200"

      response_parameters = {
        "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
        "method.response.header.Access-Control-Allow-Methods" = "'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT'"
        "method.response.header.Access-Control-Allow-Origin"  = "'*'"
      }

      #depends_on = [
       # aws_api_gateway_method_response[each.key].options_response,
      #  aws_api_gateway_integration[each.key].options_integration
      #]
    }


# ------------------------------------------------------------------
# at last, deployment
# ------------------------------------------------------------------

resource "aws_api_gateway_deployment" "deployment" {
  for_each = local.lambdas
      rest_api_id = aws_api_gateway_rest_api.apigateway[each.key].id
      stage_name = "default"

     # depends_on = [
     #   aws_api_gateway_integration[each.key].method_integration,
     #   aws_api_gateway_integration[each.key].options_integration
     # ]
}




 