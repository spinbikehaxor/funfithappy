import boto3
import datetime
import json
import jwt
import time

from datetime import datetime, timedelta
from pytz import timezone
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

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
    
    if not withinCancelWindow(class_date):
        return {
            'statusCode': 422,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("Cannot Cancel Within 3 Hours of Class")
    }
    
    #Date comes from client with time appended. Strip that off
    classDateSplit = class_date.split("/")
    classDateString = classDateSplit[0]
    cancelReservation(classDateString)
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps("Reservation Canceled")
    }
    
def withinCancelWindow(class_date):

    datetime_obj_naive = datetime.strptime(class_date, '%Y-%m-%d/%H:%M')
    datetime_obj_pacific = timezone('US/Pacific').localize(datetime_obj_naive)
    print('Class Datetime:' + str( datetime_obj_pacific))

    cut_off_time = (datetime_obj_pacific - timedelta(hours=3))
    print("Cancellation cut off window " + str(cut_off_time))

    currentTimePacific = timezone('US/Pacific').localize(datetime.now())
    print("Current time Pacific: " + str(currentTimePacific))

    if(currentTimePacific < cut_off_time):
        print("Ok you can still cancel")
        return True
    else:
        print("Too late to cancel!")
        return False
    
    
def cancelReservation(class_date):
    print("in cancelReservation")
    table = dynamodb.Table('HighLiveClassSignup')
    userformatted = username.lower().strip()
    reserved = False
    
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
    
    if(reservePosition > 0 and waitlistPosition == 0):
        returnPaidCredit(userformatted)
        reserved = True
        
    #updateListPositions(class_date, reservePosition, waitlistPosition)
    reorderPositions(class_date, reserved)
    
def reorderPositions(class_date, reserved):
    reservationList = []
    sorted_reservations = []
    capacity = getClassCapacity(class_date)
    
    #Pull all records for class date
    table = dynamodb.Table('HighLiveClassSignup')
    query_response = table.query(
        KeyConditionExpression=Key('class_date').eq(class_date)
    )
    
    #Create a sorted list based on signup time
    for reservation in query_response['Items']:
        data = {
            "username"      : reservation['username'],
            'signup_time'   : reservation['signup_time']
        }
        
        reservationList.append(data)
    sorted_reservations = sorted(reservationList, key = lambda i: i['signup_time'])
    
    print (len(sorted_reservations))
    
    #Loop through sorted list and update the roster numbers
    i = 0
    while(i < len(sorted_reservations)): 
        
        classCountIter = i + 1
        
        reservation = sorted_reservations[i]
        print(str(reservation))
        resSpot = 0
        waitSpot = 0
        
        reservation = sorted_reservations[i]
        
        #Update resSpot for people already in the class
        if classCountIter < capacity:
            resSpot = classCountIter
            
        #If a reservation was cancelled (vs a waitlist) bump the first person up from the waitlist and charge a credit    
        elif classCountIter == capacity and reserved:
            resSpot = classCountIter
            chargeCreditForBumpedUpUser(reservation['username'])
            
        #Reorder the waitlist
        elif classCountIter > capacity:
            waitSpot = classCountIter - capacity
    
        update_response = table.update_item(
            Key={
            'class_date': class_date,
            'username': reservation['username']
            },
           UpdateExpression="set reserve_position=:r, waitlist_position=:w",
            ExpressionAttributeValues={
                ':r': resSpot,
                ':w': waitSpot
            },
            ReturnValues="UPDATED_NEW"
        )
        i += 1
    
    
#Takes the position of the person cancelling, loops through other records and bumps them up the list
def updateListPositions(class_date, reservePosition, waitlistPosition):
    table = dynamodb.Table('HighLiveClassSignup')
    waitlistPulledAlready = False #Make sure you only pull one person in off the waitlist
    
    scan_response = table.query(
        #IndexName='username-index',
        KeyConditionExpression=Key('class_date').eq(class_date)
    )
    for reservation in scan_response['Items']:
        print("looping through query response")
        #If the person cancelling had a reserved spot
        if(reservePosition > 0):
            #Decrement reserved spot for people higher up on the reserved list
            if (reservation['reserve_position'] > reservePosition):
                decrementReservedPosition(reservation['class_date'], reservation['username'], (reservation['reserve_position'] -1), 0 )
            
            #Pull the first person in off the waitlist
            elif(reservation['waitlist_position'] == 1 and not waitlistPulledAlready):
                decrementReservedPosition(reservation['class_date'], reservation['username'], getClassCapacity(reservation['class_date']), 0 )
                waitlistPulledAlready = True
                chargeCreditForBumpedUpUser(reservation['username'])
                #TODO: Send this person a happy email! And charge them a credit!
            
            #Move others on the waitlist up one spot
            elif(reservation['waitlist_position'] > 1):
                decrementReservedPosition(reservation['class_date'], reservation['username'], 0, (reservation['waitlist_position'] -1) )
        
        #If the person cancelling had a waitlisted spot
        elif(waitlistPosition > 0):
            if (reservation['waitlist_position'] > waitlistPosition):
                decrementReservedPosition(reservation['class_date'], reservation['username'], 0, (reservation['waitlist_position'] -1) )
            
        
    print("updateListPositions: complete!")
    
#Bumps the next people in line up the list, one at a time. Called by updateListPositions
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

def chargeCreditForBumpedUpUser(username):
    table = dynamodb.Table('HighLiveCredits')
 
    update_response = table.update_item(
        Key={
        'username': username
        },
       UpdateExpression='SET credits = if_not_exists(credits, :zero) - :incr',
            ExpressionAttributeValues={
                ':incr': 1, ':zero': 0
            },
            ReturnValues="UPDATED_NEW"
    )
   
    
def returnPaidCredit(username):
    table = dynamodb.Table('HighLiveCredits')
    response = table.update_item(
        Key={
            'username': username
        },
        UpdateExpression='SET credits = if_not_exists(credits, :zero) + :incr',
           # ConditionExpression="credits > :zero",
            ExpressionAttributeValues={
                ':incr': 1, ':zero': 0
            },
        ReturnValues="UPDATED_NEW"
    )


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