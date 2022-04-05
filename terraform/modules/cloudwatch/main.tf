data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_cloudwatch_event_rule" "daily" {
  name                = "daily"
  description         = "Fires every 24 hours"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "reconcile_daily" {
  rule      = "${aws_cloudwatch_event_rule.daily.name}"
  target_id = "lambda"
  arn       =  "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:HighPaypalReconciliation"
}              

resource "aws_lambda_permission" "allow_cloudwatch_to_call_reconciliation" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "HighPaypalReconciliation"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.daily.arn}"
}