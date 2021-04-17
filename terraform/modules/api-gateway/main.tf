
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

module "apigateway_with_cors" {
  source  = "alparius/apigateway-with-cors/aws"
  version = "0.3.1"

  for_each = local.lambdas
    lambda_function_name = each.key
    lambda_invoke_arn    = each.value 
    http_method = "ANY"
}

 