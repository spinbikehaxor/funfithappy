import base64
import boto3
import datetime
import json
import jwt
import pytz

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime
from datetime import timedelta
from pytz import timezone

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

    for i in query_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        
        dbUser = json_data['username']
        isActiveForStream = False

        dateSigned = getWaiver(formatted_username)
        subscription_data = getPayPalSubscription(json_data['username'])
       
        if(dateSigned and (subscription_data['subscription_status'])):
            if(subscription_data['subscription_status'] == 'ACTIVE'):
                isActiveForStream = True
                
        credits = getPaidCredits(formatted_username)
        payments = getLivePaymentHistory(formatted_username)
        classHistory = getLiveClassHistory(formatted_username)
        
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
            'isActiveForStream': isActiveForStream,
            'paidLiveCredits': str(credits),
            'paymentHistory': payments,
            'classHistory': classHistory 
        }

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

def getLivePaymentHistory(username):
    table = dynamodb.Table('HighLivePayment')
    transactions = []
    sorted_payments = []
    
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    for i in query_response['Items']:
        
        transaction_date = i['transaction-date']
        transDateSplit = transaction_date.split('T')
        payment_date = transDateSplit[0]
        
        data = {
            "amount":i['amount-paid'],
            "transaction_date":payment_date,
        }
        transactions.append(data)
        
    sorted_payments = sorted(transactions, key = lambda i: i['transaction_date'], reverse=True)
    return sorted_payments
    
def getLiveClassHistory(username):
    table = dynamodb.Table('HighLiveClassSignup')
    classes = []
    sorted_classes = []
    
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username),
        IndexName="username-index"
    )
    #TODO - add clause where only get resposition > 0
    for i in query_response['Items']:
        data = {
            "classdate":i['class_date'],
            "signup_time":i['signup_time'],
        }
        classes.append(data)
        
    sorted_classes = sorted(classes, key = lambda i: i['classdate'], reverse=True)
    return sorted_classes
    
def getPaidCredits(username):
    
    table = dynamodb.Table('HighLiveCredits')
    credits = 0
    
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    for i in query_response['Items']:
        credits = i['credits']
        
    return credits

        
def getWaiver(username):
    table = dynamodb.Table('HighWaiver')
    print("looking up waiver for " + username)
    
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    for i in query_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)

        return json_data['date-signed']

    print("no waiver found for " + username)
    return None
    
def getPayPalSubscription(username):
    #Format username to look for lower case so can do faster query.
    query_username = username.lower().strip()
    table = dynamodb.Table('HighPayment')

    utcmoment_naive = datetime.utcnow()
    utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
    currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
    print("currentTimePacific: " + str(currentTimePacific))

    query_response = table.query(
        KeyConditionExpression=Key('username').eq(query_username)
    )
    
    for i in query_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        next_billing_time = json_data['next_billing_time']
        nextBillingSplit = next_billing_time.split('T')
        next_billing_date = nextBillingSplit[0]
        status = json_data['status']
        
        nextBillingDate = datetime.strptime(next_billing_date, '%Y-%m-%d')
        next_bill_pacific = timezone('US/Pacific').localize(nextBillingDate)
        print("nextBillingDate pacific formatted as date = " + str(next_bill_pacific))        
        
        #No need to call PayPal- we're good until the nextBillingDate. Updated with Nighly batch
        if( (status == "ACTIVE") or (next_bill_pacific >= currentTimePacific)):
          
            data ={
                'subscription_status': "ACTIVE",
                'nextPayment': next_billing_date
                }
            
            return data

        
    print("no payment found in database for " + username)
    data ={
        'subscription_status': 'Inactive',
        'nextPayment': 'No Payment Scheduled'
    }
    return data;
    
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
    
