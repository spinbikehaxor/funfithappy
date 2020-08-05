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
    response = table.get_item(Key={'username': username})
    
    if 'Item' not in response.keys():
        print("no record found for " + username)
        return {
            'statusCode': 400,
            'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
            'body': json.dumps('No record found for " + username')
        }
    else:

        #default to inactive
        isActiveForStream = False
        
        user_data_string = json.dumps(response['Item'])
        user_data = json.loads(user_data_string)
        
        dateSigned = getWaiver(user_data['username'], user_data['email'])
        subscription_data = getPayPalSubscription(user_data['username'])
        print(str(subscription_data))
       
        if(dateSigned and (subscription_data['subscription_status'])):
            if(subscription_data['subscription_status'] == 'ACTIVE'):
                isActiveForStream = True
        
        user ={
            'username': user_data['username'],
            'fname': user_data['fname'],
            'lname' : user_data['lname'],
            'email': user_data['email'],
            'phone': user_data['phone'],
            'preferredContact': user_data['preferredContact'],
            'waiverSignedDate': dateSigned,
            'nextPayment': subscription_data['nextPayment'],
            'isPaymentCurrent': subscription_data['subscription_status'],
            'isActiveForStream': isActiveForStream }
            
        print(str(user))
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
      
def getWaiver(username, email):
    table = dynamodb.Table('HighWaivers')
    print("looking up waiver for " + username)

    response = table.get_item(Key={'username': username, 'email' : email})
    if 'Item' not in response.keys():
        print("no waiver found for " + username)
        return None
        
    else:
        waiver_data_string = json.dumps(response['Item'])
        waiver_data = json.loads(waiver_data_string)
        return waiver_data['date-signed']
    
    print(response)
        
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
    response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    if 'Items' not in response.keys():
        print("no payment found in database for " + username)
        data ={
            'subscription_status': 'Inactive',
            'nextPayment': 'No Payment Scheduled'
        }
        return data;
    
    if(len(response['Items']) == 0 ):
        print("no payment found in table for " + username)
        data ={
            'subscription_status': 'Inactive',
            'nextPayment': 'No Payment Scheduled'
        }
        return data;
        
    payment_data_string = json.dumps(response['Items'])
        
    for item in response['Items']:
        subscription_id = item['paypal_subscription_id']
        
        auth_token = login_to_paypal();
        auth_token_param = "Bearer " + auth_token
        
        url = "https://api.paypal.com/v1/billing/subscriptions/" + subscription_id
        headers = {'Content-Type': 'application/json', 'Authorization': auth_token_param }
        
        r= requests.get(url, headers=headers)
        response_json = json.loads(r.text)
        billing_string = json.dumps(response_json['billing_info'])
        billing_data = json.loads(billing_string)
        
        data ={
            'subscription_status': response_json['status'],
            'nextPayment': billing_data['next_billing_time']
            }
        
        return data
        
      
        
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
    
