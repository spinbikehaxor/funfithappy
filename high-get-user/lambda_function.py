import base64
import boto3
import datetime
import json
import jwt
import requests

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime
from datetime import timedelta
from requests.auth import HTTPBasicAuth


def isAuthorized(jwt_token):
    secretString = json.dumps(get_secret('jwt-secret'))
    secretData = json.loads(secretString)
    JWT_SECRET = secretData['jwt-secret']
    
    JWT_ALGORITHM = 'HS256'
    JWT_EXP_DELTA_SECONDS = 20
    print("in isAuthorized," + jwt_token)
    
    if jwt_token:
        try:
            jwt_array = jwt_token.split(": ")
            jwt_value = jwt_array[1]
            jwt_value_array = jwt_value.split('\"')
            token = jwt_value_array[1]
  
            payload = jwt.decode(token, JWT_SECRET,
                                 algorithms=[JWT_ALGORITHM])
            
            if 'username' not in payload.keys():
                return False;
            
            global username 
            username = payload['username']
        except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
            print("got decoding error!" + str(e))
            return False
            
    return True

def lambda_handler(event, context):
    json_string = json.dumps(event)
    json_data = json.loads(json_string)
    headers = json_data['headers']
    found_user = False

    if 'x-api-key' not in headers.keys():
        return 
        {
            'statusCode': 401,
            'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
             'body': json.dumps("No Token Header")
         }
    else:
        authHeader = headers['x-api-key']
        
    if not isAuthorized(authHeader):
        return 
        {
            'statusCode': 401,
            'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
            'body': json.dumps('User authorization failed')
        }
    
    formatted_username = username.lower().strip()
    global dynamodb 
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('SiteUsers')
    
    query_response = table.query(
		KeyConditionExpression=Key('username').eq(formatted_username)
	)
    #scan_response = table.scan();

    for i in query_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        
        dbUser = json_data['username']
        isActiveForStream = False

        dateSigned = getWaiver(formatted_username)
        subscription_data = getPayPalSubscription(json_data['username'])
        print(str(subscription_data))
       
        if(dateSigned and (subscription_data['subscription_status'])):
            if(subscription_data['subscription_status'] == 'ACTIVE'):
                isActiveForStream = True
        
        user ={
            'username': json_data['username'],
            'fname': json_data['fname'],
            'lname' : json_data['lname'],
            'email': json_data['email'],
            'phone': json_data['phone'],
            'preferredContact': json_data['preferredContact'],
            'waiverSignedDate': dateSigned,
            'nextPayment': subscription_data['nextPayment'],
            'isPaymentCurrent': subscription_data['subscription_status'],
            'isActiveForStream': isActiveForStream }

        return {
            'statusCode': 200,
            'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
            'body': json.dumps(user)
        }
      
    return {
        'statusCode': 400,
        'headers': 
         {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
         },
        'body': json.dumps('No record found for ' + username)
    }


        
def getWaiver(username):
    table = dynamodb.Table('HighWaiver')
    print("looking up waiver for " + username)
    
    query_response = table.query(
		KeyConditionExpression=Key('username').eq(username)
	)
    for i in query_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        print(str(json_data))

        return json_data['date-signed']

    print("no waiver found for " + username)
    return None

        

    
def getPayPalSubscription(username):
    #Format username to look for lower case so can do faster query.
    query_username = username.lower().strip()
    table = dynamodb.Table('HighPayment')
    query_response = table.query(
		KeyConditionExpression=Key('username').eq(query_username)
	)
	
    for i in query_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        dbUser = json_data['username']
        transaction_date = json_data['transaction-date']
        subscription_id = json_data['paypal_subscription_id']
        next_billing_time = json_data['next_billing_time']
        nextBillingSplit = next_billing_time.split('T')
        next_billing_date = nextBillingSplit[0]
        status = json_data['status']
        
        nextBillingDate = datetime.strptime(next_billing_date, '%Y-%m-%d')
        print("nextBillingDate formatted as date = " + str(nextBillingDate))
        
        #No need to call PayPal- we're good until the nextBillingDate
        if(status == "ACTIVE" and nextBillingDate >= datetime.now()):
          
            data ={
                'subscription_status': status,
                'nextPayment': next_billing_date
                }
            
            return data
        elif(status == "ACTIVE" and nextBillingDate < datetime.now()):
            print("Looking up next billing date")
            auth_token = login_to_paypal();
            auth_token_param = "Bearer " + auth_token
            
            url = "https://api.paypal.com/v1/billing/subscriptions/" + subscription_id
            headers = {'Content-Type': 'application/json', 'Authorization': auth_token_param }
            
            print("calling paypal for subscription details")
            r= requests.get(url, headers=headers)
            response_json = json.loads(r.text)
            billing_string = json.dumps(response_json['billing_info'])
            billing_data = json.loads(billing_string)
            print("billing_data = " + str(billing_data))
            

            update_response = table.update_item(
                Key={
                'username': query_username,
                'transaction-date': transaction_date
                },
                UpdateExpression="set #status=:s, next_billing_time=:n",
                ExpressionAttributeValues={
                    ':s': response_json['status'],
                    ':n': billing_data['next_billing_time']
                },
                ExpressionAttributeNames =  {
                    '#status': 'status'
                },
                ReturnValues="UPDATED_NEW"
            )

            data ={
                'subscription_status': response_json['status'],
                'nextPayment': billing_data['next_billing_time']
                }
            
            return data
        else:
            continue
        
        
    print("no payment found in database for " + username)
    data ={
        'subscription_status': 'Inactive',
        'nextPayment': 'No Payment Scheduled'
    }
    return data;
    

def login_to_paypal():
    print('in login_to_paypal')
    paypal_client_id = "ARFAJ4v0DMU0-jp__jkVEVNYP139DlETKokloLrUywQ0qjlOs0H5x1ETIVDJARd3rBuCPJHGKWrdZ2fY"
    
    secretString = json.dumps(get_secret('PaypalSecret'))
    secretData = json.loads(secretString)
    paypalSecret = secretData['PaypalSecret']
    
    print("calling test")
    testurl = 'https://www.google.com'
    tr = requests.get(testurl)
    print(str(tr))
    
    url = "https://api.paypal.com/v1/oauth2/token"
    payload= {'grant_type': 'client_credentials'}

    r= requests.post(url, payload, auth=HTTPBasicAuth(paypal_client_id, paypalSecret))
    response_dict = r.text
    json_data = json.loads(response_dict)
    token = json_data['access_token']
    return token
    
def get_secret(secret_name):
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
            return json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return json.loads(decoded_binary_secret)
    

