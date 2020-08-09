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
            
    global dynamodb 
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighUsers')
    scan_response = table.scan();

    for i in scan_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        
        dbUser = json_data['username']

        if(dbUser.lower().strip() == username.lower().strip()):
            #default to inactive
            isActiveForStream = False
        
            
            dateSigned = getWaiver(json_data['username'], json_data['email'])
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
      
        else:
            continue
            
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


        
def getWaiver(username, email):
    table = dynamodb.Table('HighWaivers')
    print("looking up waiver for " + username)
    
    scan_response = table.scan();

    for i in scan_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        
        dbUser = json_data['username']
        if(dbUser.lower().strip() == username.lower().strip()):
            return json_data['date-signed']
        else:
            continue

    print("no waiver found for " + username)
    return None

        
def getMostRecentPayment(username):
    table = dynamodb.Table('HighPayment')
    mostRecentPayment = datetime.now() - timedelta(days=365)
    
    response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )

    if 'Items' not in response.keys():
        print("no payment found for " + username)
        return None
    
    if(len(response['Items']) == 0 ):
        print("no payment found for " + username)
        return None
    
    payment_data_string = json.dumps(response['Items'])
    for item in response['Items']:
        try:
            transactionString = item['transaction-date'].split('T')
            transactionDate = datetime.strptime(transactionString[0], '%Y-%m-%d')
        except ValueError as ve:
            print("Date string not in expected format")
            
        if(transactionDate > mostRecentPayment):
            mostRecentPayment = transactionDate
            
    return mostRecentPayment
    
def getPayPalSubscription(username):
    table = dynamodb.Table('HighPayment')
    
    scan_response = table.scan();

    for i in scan_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        dbUser = json_data['username']
        if(dbUser.lower().strip() == username.lower().strip()):
            subscription_id = json_data['paypal_subscription_id']
            print("subscription_id = " + subscription_id)
            
            auth_token = login_to_paypal();
            auth_token_param = "Bearer " + auth_token
            
            url = "https://api.paypal.com/v1/billing/subscriptions/" + subscription_id
            headers = {'Content-Type': 'application/json', 'Authorization': auth_token_param }
            
            r= requests.get(url, headers=headers)
            response_json = json.loads(r.text)
            billing_string = json.dumps(response_json['billing_info'])
            billing_data = json.loads(billing_string)
            print("billing_data = " + str(billing_data))
            
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
    
