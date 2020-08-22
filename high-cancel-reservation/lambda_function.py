import boto3
import datetime
import json
import jwt

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime

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
    body = json_data['body']
    body_json = json.loads(body)
    class_date = body_json['class_date']
    
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
    
    cancelReservation(class_date)
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps("Reservation Canceled")
    }

def cancelReservation(class_date):
    table = dynamodb.Table('HighLiveClassSignup')
    userformatted = username.lower().strip()
    
    #Get the positions first so can update the roster
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(userformatted) & Key('class_date').eq(class_date)
    )
    for reservation in query_response['Items']:

        reservePosition = reservation['reserve_position']
        waitlistPosition = reservation['waitlist_position']
    
    response = table.delete_item(
            Key={
                'username': userformatted,
                'class_date': class_date
            
            }
        )
    decrementSpotsTaken(class_date)
    updateListPositions(class_date, reservePosition, waitlistPosition)
    
#Takes the position of the person cancelling, loops through other records and bumps them up the list
def updateListPositions(class_date, reservePosition, waitlistPosition):
    table = dynamodb.Table('HighLiveClassSignup')
    waitlistPulledAlready = False #Make sure you only pull one person in off the waitlist
    
    scan_response = table.scan(
        FilterExpression=Key('class_date').eq(class_date)
    )
    for reservation in scan_response['Items']:

        #If the person cancelling had a reserved spot
        if(reservePosition > 0):
            #Decrement reserved spot for people higher up on the reserved list
            if (reservation['reserve_position'] > reservePosition):
                decrementReservedPosition(reservation['class_date'], reservation['username'], (reservation['reserve_position'] -1), 0 )
            
            #Pull the first person in off the waitlist
            elif(reservation['waitlist_position'] == 1 and not waitlistPulledAlready):
                decrementReservedPosition(reservation['class_date'], reservation['username'], getClassCapacity(reservation['class_date']), 0 )
                waitlistPulledAlready = True
                #TODO: Send this person a happy email!
            
            #Move others on the waitlist up one spot
            elif(reservation['waitlist_position'] > 1):
                decrementReservedPosition(reservation['class_date'], reservation['username'], 0, (reservation['waitlist_position'] -1) )
        
        #If the person cancelling had a waitlisted spot
        elif(waitlistPosition > 0):
            if (reservation['waitlist_position'] > waitlistPosition):
                decrementReservedPosition(reservation['class_date'], reservation['username'], 0, (reservation['waitlist_position'] -1) )
            
   	    
    print("updateListPositions: complete!")
    
#Bumps the next people in line up the list, one at a time. Called by updateListPisitions
def decrementReservedPosition(class_date, username, reservePosition, waitlistPosition):
    table = dynamodb.Table('HighLiveClassSignup')
 
    update_response = table.update_item(
        Key={
        'username': username,
        'class_date': class_date
        },
       UpdateExpression='SET reserve_position = :reservePosition, waitlist_position = :waitlistPosition',
            ExpressionAttributeValues={
                ':reservePosition': reservePosition, ':waitlistPosition': waitlistPosition
            },
            ReturnValues="UPDATED_NEW"
    )
    print("Updated " + username + " to reservation " + str(reservePosition) + " waitlistPosition " + str(waitlistPosition))
    


def decrementSpotsTaken(class_date):
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighClasses')
    
    classDateObj = datetime.strptime(class_date, '%Y-%m-%d')
    class_year = classDateObj.strftime( "%Y")
    
    try:
        response = table.update_item(
            Key={
                'class_date': class_date,
                'class_year': class_year
            },
            UpdateExpression='SET #spots_taken = if_not_exists(#spots_taken, :zero) - :incr',
            ConditionExpression="#spots_taken > :zero",
            ExpressionAttributeNames =  {
                    '#spots_taken': 'spots_taken'
                },
            ExpressionAttributeValues={
                ':incr': 1, ':zero': 0
            },
            ReturnValues="UPDATED_NEW"
        )
    except ClientError as e:
        if e.response['Error']['Code'] == "ConditionalCheckFailedException":
            print(e.response['Error']['Message'])
        else:
            raise
    else:
        return response
        
        
def getClassCapacity(class_date):
    
    #Step 1: Get Location
    table = dynamodb.Table('HighClasses')
    location = ''
    classDateObj = datetime.strptime(class_date, '%Y-%m-%d')
    class_year = classDateObj.strftime( "%Y")
  
    response = table.query(
        KeyConditionExpression=Key('class_year').eq(class_year) & Key('class_date').eq(class_date)
    )
    
    for i in response['Items']:
        location = i['location']
    

    #Step 2: Get Capacity for Location
    table = dynamodb.Table('HighLocation')
  
    response = table.query(
        KeyConditionExpression=Key('name').eq(location)
    )
    for i in response['Items']:
        capacity = i['capacity']
        return capacity
    
    

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