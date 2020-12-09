import base64
import boto3
import json
import jwt
import pytz

from boto3.dynamodb.conditions import Key
from datetime import datetime, timedelta
from dateutil import parser
from pytz import timezone

def isAuthorized(jwt_token):
    secretString = json.dumps(get_secret('jwt-secret'))
    secretData = json.loads(secretString)
    
    JWT_SECRET = secretData['jwt-secret']
    JWT_ALGORITHM = 'HS256'
    JWT_EXP_DELTA_SECONDS = 20
    print("in isAuthorized, token = " + jwt_token)
    
    if jwt_token:
        try:
            jwt_array = jwt_token.split(": ")
            jwt_value = jwt_array[1]
            jwt_value_array = jwt_value.split('\"')
            token = jwt_value_array[1]
    
            payload = jwt.decode(token, JWT_SECRET,
                                 algorithms=[JWT_ALGORITHM])
            
            if 'username' not in payload.keys():
                print("username not found in token")
                return False;
            
            global username 
            username = payload['username']
        except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
            print("got decoding error!" + str(e))
            return False
    return True

def authorizeUser(headers):
    print("checking for api key")
    if 'x-api-key' not in headers.keys():
        return False
       
    else:
        authHeader = headers['x-api-key']
        if not isAuthorized(authHeader):
            return False
        
        return True

def lambda_handler(event, context):
    print(str(event))
    print("in lambda_handler")
    json_string = json.dumps(event)
    print(json_string)
    json_data = json.loads(json_string)
    if not authorizeUser(json_data['headers']):
        return {
            'statusCode': 401,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps('User is not logged in')
        }
    print("username = " + username)
    usernameformatted = username.lower().strip()
    
    if not isDuringSaleWindow():
        return {
            'statusCode': 422,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps('Black Friday Sale is not Active')
        }
        
    
    eligible = isEligibleForBlackFriday(usernameformatted)
    if not eligible:
        return {
            'statusCode': 422,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps('2 Sale Packages already purchased!')
        }
    else:
        return {
        'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps('User is eligible!')
        }


def isEligibleForBlackFriday(username):
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighLivePayment')
    blackFridayCount = 0
    
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
        
    for i in query_response['Items']:
        amount_paid = i['amount-paid']
        if amount_paid == "50.00":
            print("found prior $50 transaction")
            blackFridayCount = blackFridayCount + 1
        else:
            print("found non-sale transaction")
    
    if blackFridayCount >= 2:
        return False
    else:
        return True
        
        
def isDuringSaleWindow():
    saleStartDate = "2020-11-27"
    saleEndDate = "2020-11-30"
    
    currentTimePacific = str(getCurrentTimePacific())
    currentTimeSplit = currentTimePacific.split(" ")
    currentDate = currentTimeSplit[0]
    #currentDate = "2020-11-29"


    print ("currentDate = " + currentDate)
    
    if currentDate >= saleStartDate and currentDate <= saleEndDate:
        print("Black Friday Sale is ON!")
        return True
    else:
        print("Not time for Black Friday Sale")
        return False
    
    
def getCurrentTimePacific():
    utcmoment_naive = datetime.utcnow()
    utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
    currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
    return currentTimePacific
        
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