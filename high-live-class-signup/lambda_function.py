import base64
import boto3
import datetime
import json
import jwt

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from datetime import datetime
from datetime import timedelta
from decimal import *


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
            print("HighLiveClassSignup: username is " + username)
        except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
            print("got decoding error!" + str(e))
            return False
            
    return True

def lambda_handler(event, context):
    global dynamodb 
    
    json_string = json.dumps(event)
    json_data = json.loads(json_string)
    headers = json_data['headers']
    body = json_data['body']
    
    found_user = False

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
    
    if not hasSignedWaiver(username):
        return {
            'statusCode': 401,
            'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
            'body': json.dumps('Please complete the waiver prior to reserving a spot in class')
        }
        
    body_json = json.loads(body)
    class_date = body_json['class_date']
    class_type = body_json['class_type']
    if class_type =="Boot":
        class_type = "Boot Camp"
    
    class_details = getClassDetails(class_date, class_type)
    isFree = class_details['isFree']

    capacity = class_details['capacity']
    
    if isFree == "False" and not hasPaidCredits(username, class_type):
        return {
            'statusCode': 422,
            'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
            'body': json.dumps('Please purchase class credits prior to reserving a spot in class')
        }
    
    spotNumber = signup(class_details['class_date'], capacity, isFree, class_type)
    if(spotNumber == -1):
        return {
            'statusCode': 422,
            'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
            'body': json.dumps('You already have a reservation for the requested class')
        }
    
    #Update capacity for double classes
    elif (class_type =="Boot-Low"):
        print("boot-low combo! Need to incrementSpotsTaken for both individual classes")
        low_class_details = getClassDetails(class_date, "High-Low")
        incrementSpotsTaken(low_class_details['class_date'])
        
        boot_class_details = getClassDetails(class_date, "Boot Camp")
        incrementSpotsTaken(boot_class_details['class_date'])
    
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps(spotNumber)
    }
    
def hasPaidCredits(username, class_type):
    table = dynamodb.Table('HighLiveCredits')
    
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    
    creditThreshold = 1
    if( class_type == "Boot-Low"):
        creditThreshold = 1.5
        
    for i in query_response['Items']:
        credits = i['credits']
        if credits > creditThreshold:
            return True
    
    return False
            
            
def decrementPaidCredits(username, class_type):
    table = dynamodb.Table('HighLiveCredits')
    
    creditCost = '1'
    
    if(class_type == "Boot-Low"):
        creditCost = '1.5'
        
    response = table.update_item(
        Key={
            'username': username
        },
        UpdateExpression='SET credits = if_not_exists(credits, :zero) - :decr',
            ConditionExpression="credits > :zero",
            ExpressionAttributeValues={
                ':decr': Decimal(creditCost), ':zero': 0
            },
        ReturnValues="UPDATED_NEW"
    )
            
    
def signup(class_date, capacity, isFree, class_type):
    print("in signup, class_date = " + class_date)
    table = dynamodb.Table('HighLiveClassSignup')
    
    signup_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    formatted_username = username.strip().lower()
    spotNumber = getSpotNumber(formatted_username, class_date)
    reserve_position = 0
    waitlist_position = 0
    
    if(spotNumber <= capacity):
        reserve_position = spotNumber
        
    else:
        waitlist_position = (spotNumber - capacity)
    
    try:
        response = table.put_item(
            Item={
                'username': formatted_username,
                'class_date': class_date,
                'signup_time': signup_time,
                'reserve_position' : reserve_position,
                'waitlist_position': waitlist_position
            },
            ConditionExpression='username <> :formatted_username AND class_date <> :class_date',
            ExpressionAttributeValues={':formatted_username': formatted_username, ':class_date' : class_date},
        )
        incrementSpotsTaken(class_date)
    except ClientError as e:
        print(str(e))
        return -1
        
    #Only charge a credit if not on waitlist
    if isFree == "False":
        print("class is paid - charging!")
        if waitlist_position == 0 and reserve_position > 0:
            decrementPaidCredits(formatted_username, class_type)
        
    
    return spotNumber
        
def getClassDetails(class_date, class_type):
    print("in getClassDetails, class_date = " + class_date + " class_type = " + class_type) 
    #Step 1: Get Location
    table = dynamodb.Table('HighClasses')
    location = ''
    classDateObj = class_date.split("-")
    class_year = classDateObj[0]
    isFree = False
  
    response = table.query(
        KeyConditionExpression=Key('class_year').eq(class_year) & Key('class_date').begins_with(class_date),
        FilterExpression=Attr('class_type').begins_with(class_type)
    )
    print("length of response for class details = " + str(len(response['Items'])))
    
    for i in response['Items']:
        class_date_full = i['class_date']
        location = i['location']
        if 'isFree' in i.keys():
            isFree = i['isFree']
    
    #Step 2: Get Capacity for Location
    table = dynamodb.Table('HighLocation')
  
    response = table.query(
        KeyConditionExpression=Key('name').eq(location)
    )
    for i in response['Items']:
        capacity = i['capacity']
        
        
    data = {
        'location' : location,
        'capacity' : capacity,
        'isFree' : isFree,
        'class_date': class_date_full
    }
    return data
    

def getSpotNumber(username, class_date):
    table = dynamodb.Table('HighLiveClassSignup')
    
    response = table.query(
        KeyConditionExpression=Key('class_date').eq(class_date)
    )
    #responseString = json.dumps(response)
    topCurrentSpot = response['Count']
    spotNumber = topCurrentSpot + 1
    print('Reservation spot =  ' + str(spotNumber))
    return spotNumber
    
def incrementSpotsTaken(class_date):
    print("in incrementSpotsTaken, class_date = " + class_date)
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighClasses')
    
    classDateSplit = class_date.split("-")
    #classDateObj = datetime.strptime(class_date, '%Y-%m-%d')
    class_year = classDateSplit[0]

    response = table.update_item(
        Key={
            'class_year': class_year,
            'class_date': class_date
        },
        #UpdateExpression='set spots_taken = spots_taken + :val',
        UpdateExpression='SET #spots_taken = if_not_exists(#spots_taken, :zero) + :incr',
        ExpressionAttributeNames =  {
                '#spots_taken': 'spots_taken'
            },
        ExpressionAttributeValues={
            ':incr': 1, ':zero': 0
        },
        ReturnValues="UPDATED_NEW"
    )
        
def hasSignedWaiver(username):
    table = dynamodb.Table('HighWaiver')
    
    response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )

    for i in response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        
        dbUser = json_data['username']
        if(dbUser.lower().strip() == username.lower().strip()):
            return True
        else:
            continue

    print("no waiver found for " + username)
    return False
    

        
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
