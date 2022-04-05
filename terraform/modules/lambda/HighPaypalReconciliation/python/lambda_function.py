import boto3
import datetime
import json
import logging
import requests
from boto3.dynamodb.conditions import Attr
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError



def lambda_handler(event, context):
    authtoken = login_to_paypal()
    print("got paypal auth token!")

    checkForMissingPayments(authtoken)



def login_to_paypal():
    print('in login_to_paypal')
    paypal_client_id = "AdZElbtqtQWLMeTh9oI1d4ZaYkbj8gUNXEyaRLpRYVwgOd_MtW48DSmc8MEBlUNDLXJzl5uPoiCmTUXV"

    secretString = json.dumps(get_secret('PaypalSecret'))
    secretData = json.loads(secretString)
    paypalSecret = secretData['PaypalSecret']
    
    url = "https://api.paypal.com/v1/oauth2/token"
    payload= {'grant_type': 'client_credentials'}

    r= requests.post(url, payload, auth=HTTPBasicAuth(paypal_client_id, paypalSecret))
    response_dict = r.text
   # print(f"called paypal login {response_dict}")
    json_data = json.loads(response_dict)
    token = json_data['access_token']

    auth_token_param = "Bearer " + token
    return auth_token_param

    #If someone closes their paypal window or things go wonky with their Javascript...
def checkForMissingPayments(authtoken):

    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighPayment')

    #We're going to look for all new transactions in the last 24 hours
    print("in checkForMissingPayments")
    end_date = datetime.now()
    end_date_string = end_date.strftime("%Y-%m-%d" + "T" + "%H:%M:%S" + "Z")
    start_date = end_date - relativedelta(days=3)
    start_date_string = start_date.strftime("%Y-%m-%d" + "T" + "%H:%M:%S" + "Z")

    #Prep and fire off the REST request to Paypal
    baseurl = "https://api.paypal.com/v1/reporting/transactions"
    finalurl = baseurl + "?start_date=" + start_date_string +"&end_date=" + end_date_string
    print("finalurl = " + finalurl)
    headers = {'Content-Type': 'application/json', 'Authorization': authtoken }
    r= requests.get(finalurl, headers=headers)
    response_json = json.loads(r.text)

    print(f"response to checkForMissingPayments {response_json}")

    
    #Iterate through all transactions from last 24 hours
    for i in response_json['transaction_details']:
        transaction = i['transaction_info']

        #This means it's not a subscription
        if 'paypal_reference_id_type' not in transaction.keys():
            checkForMissingLivePayments(transaction['transaction_id'], authtoken)
            continue

        transaction_type = transaction['paypal_reference_id_type']

        #Right now we're only concerned with subscriptions... this will change
        if(transaction_type == "SUB"): 
            subscription_id = transaction['paypal_reference_id']
            print("looking for sub " + subscription_id)

            #Query dynamo to see if we captured this subscription
            scan_response = table.scan(
                FilterExpression=Attr('paypal_subscription_id').eq(subscription_id)
                )

            is_sub_missing = True

            for i in scan_response['Items']:
                json_string = json.dumps(i)
                json_data = json.loads(json_string)
                sub_id = json_data['paypal_subscription_id']

                print(f"subscription {sub_id} found")
                if(sub_id == subscription_id):
                    print("found " + subscription_id)
                    is_sub_missing = False;
                    continue #We've got this one - yay!
                else: #If missing, email your damn self to fix this shit! Can't just insert because the name/email might not match
                    print(f"Booo - didn't find {subscription_id}")
            
            if is_sub_missing: 
                print("sending email!")
                sendEmail(subscription_id)


def checkForMissingLivePayments(transactionId, authtoken):
    print("in checkForMissingLivePayments - looking for capture " + transactionId)
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighLivePayment')

    #Search returns the captureId (lame!). We need the order Id, so grab it...
    url = "https://api.paypal.com/v2/payments/captures/" + transactionId
    headers = {'Content-Type': 'application/json', 'Authorization': authtoken }
    r= requests.get(url, headers=headers)
    response_json = json.loads(r.text)

    for i in response_json['links']:
        linkType = i['rel']
        if linkType == "up":
            transactionLink = i['href']
            transactionStringSplit = transactionLink.split('orders/')
            transactionId = transactionStringSplit[1]
            print("found orderId " + transactionId + " checking if captured")

            scan_response = table.scan(
                FilterExpression=Attr('paypal_order_id').eq(transactionId)
                )

            if(len(scan_response['Items']) > 0):
                print("found " + transactionId)
                continue #We've got this one - yay!
            else: 
               sendEmail(transactionId)




def sendEmail(subscription_id):
    print(f'in sendEmail for {subscription_id}!')
    SENDER = "funfithappy.ca@gmail.com"
    AWS_REGION = "us-east-2"
    SUBJECT = "Missing Payment!"
    CHARSET = "UTF-8"

    BODY_TEXT = ("Missing Payment! Reconcile subscription " + subscription_id)
    BODY_HTML = """<html><head></head><body>
  <h1>Missing Payment!</h1>
  <p>Reconcile subscription """ + subscription_id + """</p> 
</body></html>
 """
    email = ["funfithappy.ca@gmail.com"]
    client = boto3.client('ses',region_name=AWS_REGION)


    try:
    #Provide the contents of the email.
        print("sending email to " + str(email))
        response = client.send_email(
            Destination={
                'ToAddresses': 
                     email
                ,
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML,
                        },
                    'Text': {
                        'Charset': CHARSET,
                        'Data': BODY_TEXT,
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            Source=SENDER,
        # If you are not using a configuration set, comment or delete the
        # following line
        #ConfigurationSetName=CONFIGURATION_SET,
    )
# Display an error if something goes wrong. 
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps('Reconcilation Email Sent!')
    }

    


def updateLocalRecord(username, transaction_date, status, next_billing_time):
    print("in updateLocalRecord for user " + username )

    #This is a hack :P Paypal puts a T between the data and time and my code looks for it if there's a record.
    if not next_billing_time:
        next_billing_time = "1900-01-01T"

    update_response = table.update_item(
                Key={
                'username': username,
               'transaction-date': transaction_date
                },
               UpdateExpression="set #status=:s, next_billing_time=:n",
                ExpressionAttributeValues={
                    ':s': status,
                    ':n': next_billing_time
                },
                ExpressionAttributeNames =  {
                    '#status': 'status'
                },
                ReturnValues="UPDATED_NEW"
            )
    print("Update complete! " + str(update_response))


def get_secret(secret_name):
    print("in get_secret")
    region_name = "us-east-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        print("about to retrieve value")
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print("error retrieving secret " + str(e))
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            print("returning secret")
            return json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            print("returning secret")
            return json.loads(decoded_binary_secret)