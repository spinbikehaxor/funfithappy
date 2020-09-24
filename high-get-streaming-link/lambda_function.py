import boto3
import datetime
import json
import jwt
import pytz

from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
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
    
    
    global dynamodb 
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    
    if withinStreamingWindow():
        
        writeStatsForUser(username)
       
        table = dynamodb.Table('HighVideoLink')
        query_response = table.query(
        KeyConditionExpression=Key('classname').eq('high')
        )

        for i in query_response['Items']:
            json_string = json.dumps(i)
            json_data = json.loads(json_string)
            
            url = json_data['url']
            body = {"url" : url}
        
        return {
            'statusCode': 200,
            'headers': 
                 {
                    'Access-Control-Allow-Headers': '*',
                    'Access-Control-Allow-Origin':  '*',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
                 },
            'body': json.dumps(body)
        }
   
    return {
    'statusCode': 200,
    'headers': 
         {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
         },
    'body': json.dumps("No Active Stream at this Time")
    }

def getCurrentTimePacific():
    utcmoment_naive = datetime.utcnow()
    utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
    currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
    return currentTimePacific

def withinStreamingWindow():
    print("in withinStreamingWindow")
    #Get the current time in the Pacific Time Zone
    global currentTimePacific 
    global streamTime
    currentTimePacific = getCurrentTimePacific()
    todayDayOfWeek = currentTimePacific.strftime("%A")

    #Get datetime again but this time for the stream - will update shortly
    stream_naive = datetime.utcnow()
    stream_moment = stream_naive.replace(tzinfo=pytz.utc)
    streamStartTime = stream_moment.astimezone(timezone('US/Pacific'))

    print("Looking up times for " + todayDayOfWeek)
    #Pull streaming times for the current day (if any)
    table = dynamodb.Table('HighStreamingTimes')
    query_response = table.query(
        KeyConditionExpression=Key('day_of_week').eq(todayDayOfWeek)
    )
    
    for i in query_response['Items']:
            json_string = json.dumps(i)
            json_data = json.loads(json_string)
            
            streamTime = json_data['time_of_day']
            streamTimeSplit = streamTime.split(':')
            streamHour = int(streamTimeSplit[0])
            streamMin = int(streamTimeSplit[1]) 
            
            streamStartTime = streamStartTime.replace(hour=streamHour, minute=streamMin)
            streamStartTime = (streamStartTime - timedelta(minutes=1))
            cut_off_time = (streamStartTime + timedelta(hours=1, minutes=2))
            
            print("found a streaming time for today! " + str(streamStartTime.time()) + " with cutoff " + str(cut_off_time.time()))
            print("currentTimePacific = " + str(currentTimePacific.time()))
            
            if (currentTimePacific.time() >= streamStartTime.time()) and (currentTimePacific.time() < cut_off_time.time()):
                print("Woo Hoo Active Stream Time!!")
                return True
        
    return False

def writeStatsForUser(username):
    classdate = datetime.strftime(currentTimePacific,"%Y-%m-%d")
    table = dynamodb.Table('HighStreamStats')
    
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)&Key('date').eq(classdate)
    )
    
    #Only write to the table if you haven't already
    if(len(query_response['Items']) > 0):
        return

    response = table.put_item(
        Item={
            'date': str(classdate),
            'username': username,
            'class_time': str(streamTime)
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