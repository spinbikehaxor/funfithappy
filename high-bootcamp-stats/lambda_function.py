import boto3
import datetime
import json
import jwt
import pytz

from datetime import datetime, timedelta
from boto3.dynamodb.conditions import Key, Attr
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
    #body = json_data['body']
    
    if 'x-api-key' not in headers.keys():
        return {
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
        print("not authorized")
        return {
            'statusCode': 401,
            'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
            'body': json.dumps('User authorization failed')
        }
    
    body = json.loads(json_data['body'])
    classname = body['classname']
    classtype = body['class_type']
    
    global dynamodb 
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    
    writeStatsForUser(username, classname, classtype)
   
    return {
        'statusCode': 200,
        'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
        'body': json.dumps("Bootcamp stats written for user " + username)
        }
   

def getCurrentTimePacific():
    utcmoment_naive = datetime.utcnow()
    utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
    currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
    return currentTimePacific


def writeStatsForUser(username, classname, classtype):
    currentTimePacific = getCurrentTimePacific()
    classdate = datetime.strftime(currentTimePacific,"%Y-%m-%d")
    classTime = datetime.strftime(currentTimePacific,"%H:%M")
    classHour = datetime.strftime(currentTimePacific,"%H")
    table = dynamodb.Table('HighStreamStats')
    
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username),
        IndexName="username-index",
        FilterExpression=Attr('class_date').eq(classdate)
    )
    
    for i in query_response['Items']:
        print("looping!")
        query_class_type = i['class_type']
        query_class_time = i['class_time']
        query_class_name = i['class_name']
        
        query_class_split = query_class_time.split(':')
        query_hour = query_class_split[0]
        print("query_hour = " + query_hour + " classHour = " + classHour + " query_class_type = " + query_class_type + " classtype = " + classtype +
        " query_class_name = " + query_class_name + " classname = " + classname)
        
        #Don't double record the same class if they hit play multiple times.
        if query_hour == classHour and query_class_type == classtype and query_class_name == classname:
            print("found dup - not logging")
            return
        
    response = table.put_item(
        Item={
            'date': str(currentTimePacific),
            'username': username,
            'class_type': classtype,
            'class_name': classname,
            'class_date' : classdate,
            'class_time' : classTime
        }
    )

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