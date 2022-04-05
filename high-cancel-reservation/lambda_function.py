import boto3
import datetime
import json
import jwt
import time
import pytz

from datetime import datetime, timedelta
from pytz import timezone
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
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
    print("body_json = " + str(body_json))
    class_date = body_json['class_date']
    class_type = body_json['class_type']

    #Date comes from client with time appended. Strip that off
    classDateSplit = class_date.split("/")
    classDateString = classDateSplit[0]
    print("classDateString" + classDateString)
    
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

    class_details = getClassDetails(classDateString, class_type)
    isFree = class_details['isFree']

    #Let free classes be canceled at any time
   # if not isFree:
       # if not withinCancelWindow(classDateString, class_details['class_time']):
         #   return {
           #     'statusCode': 422,
         #       'headers': {
          #          'Access-Control-Allow-Headers': '*',
         #           'Access-Control-Allow-Origin':  '*',
        #            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        #        },
         #       'body': json.dumps("Cannot Cancel Within 3 Hours of Class")
        #    }
    
    cancelReservation(class_details['class_date'], isFree, int(class_details['capacity']), class_type)

    #Update capacity for double classes
    if (class_type =="Boot-Low Combo"):
        print("boot-low combo! Need to decrementSpotsTaken for both individual classes")
        low_class_details = getClassDetails(classDateString, "High-Low")
        decrementSpotsTaken(low_class_details['class_date'])
        
        boot_class_details = getClassDetails(classDateString, "Boot Camp")
        decrementSpotsTaken(boot_class_details['class_date'])
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps("Reservation Canceled")
    }
    
def withinCancelWindow(class_date, classtime):

    classTimeStamp = class_date + "/" + classtime

    datetime_obj_naive = datetime.strptime(classTimeStamp, '%Y-%m-%d/%H:%M')
    datetime_obj_pacific = timezone('US/Pacific').localize(datetime_obj_naive)
    print('Class Datetime:' + str( datetime_obj_pacific))

    cut_off_time = (datetime_obj_pacific - timedelta(hours=3))
    print("Cancellation cut off window " + str(cut_off_time))   

    utcmoment_naive = datetime.utcnow()
    utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
    currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))

   # currentTimePacific = timezone('US/Pacific').localize(datetime.now())
    print("Current time Pacific: " + str(currentTimePacific))

    if(currentTimePacific < cut_off_time):
        print("Ok you can still cancel")
        return True
    else:
        print("Too late to cancel!")
        return False
    
    
def cancelReservation(class_date, isFree, capacity, class_type):
    print("in cancelReservation, class_date = " + class_date)
    table = dynamodb.Table('HighLiveClassSignup')
    userformatted = username.lower().strip()
    reserved = False
    print("cancelling class for " + userformatted)
    
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
    
    if not isFree:
        print("Not free so checking spot to return credit")
        if(reservePosition > 0 and waitlistPosition == 0):
            print("reserved spot so returning credit")
            returnPaidCredit(userformatted, class_type)
            reserved = True
        
    reorderPositions(class_date, reserved, isFree, capacity, class_type)
    
def reorderPositions(class_date, reserved, isFree, capacity, class_type):
    reservationList = []
    sorted_reservations = []
    
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
    
    #print (len(sorted_reservations))
    
    #Loop through sorted list and update the roster numbers
    i = 0
    while(i < len(sorted_reservations)): 
        
        classCountIter = i + 1
        
        reservation = sorted_reservations[i]
        #print(str(reservation))
        resSpot = 0
        waitSpot = 0
        
        reservation = sorted_reservations[i]
        
        #Update resSpot for people already in the class
        if classCountIter < capacity:
            resSpot = classCountIter

        #Waitlist cancelation
        elif classCountIter == capacity and not reserved:
            resSpot = classCountIter
            
        #If a reservation was cancelled (vs a waitlist) bump the first person up from the waitlist and charge a credit    
        elif classCountIter == capacity and reserved:
            resSpot = classCountIter
            if not isFree:
                chargeCreditForBumpedUpUser(reservation['username'], class_type)
                email = getEmailForUser(reservation['username'])
                sendReservedEmail(email, class_date, class_type)
            
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
    

def chargeCreditForBumpedUpUser(username, class_type):
    table = dynamodb.Table('HighLiveCredits')

    creditAmount = 1
    if(class_type =="Boot-Low Combo"):
        creditAmount = 1.5
 
    update_response = table.update_item(
        Key={
        'username': username
        },
       UpdateExpression='SET credits = if_not_exists(credits, :zero) - :incr',
            ExpressionAttributeValues={
                ':incr': Decimal(creditAmount), ':zero': 0
            },
            ReturnValues="UPDATED_NEW"
    )
   
    
def returnPaidCredit(username, class_type):
    table = dynamodb.Table('HighLiveCredits')

    creditAmount = 1
    if(class_type =="Boot-Low Combo"):
        creditAmount = 1.5

    response = table.update_item(
        Key={
            'username': username
        },
        UpdateExpression='SET credits = if_not_exists(credits, :zero) + :incr',
           # ConditionExpression="credits > :zero",
            ExpressionAttributeValues={
                ':incr': Decimal(creditAmount), ':zero': 0
            },
        ReturnValues="UPDATED_NEW"
    )


def decrementSpotsTaken(class_date):
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighClasses')
    
    classDateSplit = class_date.split("-")
    class_year = classDateSplit[0]
    
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

def getClassDetails(class_date, class_type):
    print("in getClassDetails " + class_date + " " + class_type)
    #Step 1: Get Location
    table = dynamodb.Table('HighClasses')
    location = ''
    classDateObj = class_date.split("-")
    class_year = classDateObj[0]
    isFree = False
    class_time = ''
  
    response = table.query(
        KeyConditionExpression=Key('class_year').eq(class_year) & Key('class_date').begins_with(class_date),
        FilterExpression=Attr('class_type').begins_with(class_type)
    )
    
    for i in response['Items']:
        location = i['location']
        class_time = i['class_time']
        class_date_full = i['class_date']
        if 'isFree' in i.keys():
            isFreeString = i['isFree']
            if isFreeString == "True":
                isFree = True

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
        'class_time' : class_time,
        'class_date': class_date_full
    }
    return data

def getEmailForUser(username):
    print("in getEmailForUser, username is " + username)
    table = dynamodb.Table('SiteUsers')
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    for i in query_response['Items']:
        email = i['email']
        return email


def sendReservedEmail(email, class_date, class_type):
    print("in sendEmail")
    
    #strip ugly timestamp gak off of time
    class_date = class_date.split(" ")[0]

    SENDER = "funfithappy.ca@gmail.com"
    AWS_REGION = "us-east-2"
    SUBJECT = str(class_date) + " " + class_type +  ": You're In! "
    CHARSET = "UTF-8"

    BODY_TEXT = (str(class_date) + " " + class_type +  ": You're In! ")
    BODY_HTML = """<html><head></head><body>
  <h1>""" + str(class_date) + """  """ + class_type + """: You're In!</h1>
  <p>Hello! We have had a cancellation for the  """ + class_type + """ Class scheduled for """ + str(class_date) + """  and you now have a reserved spot. If you can no longer make it, please cancel prior to 3 hours before class to ensure a refunded credit.</p>
</body></html>
 """
    client = boto3.client('ses',region_name=AWS_REGION)

    try:
    #Provide the contents of the email.
        print("sending email to " + str(email))
        emailList = []
        emailList.append(email)
        response = client.send_email(
            Destination={
                'ToAddresses': 
                     emailList
                ,
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML,
                        },
                    'Text': {
                        'Charset': CHARSET,
                        'Data': BODY_TEXT,
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            Source=SENDER,
        # If you are not using a configuration set, comment or delete the
        # following line
        #ConfigurationSetName=CONFIGURATION_SET,
    )
# Display an error if something goes wrong. 
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps('Relocation Notification Email Sent!')
    }

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