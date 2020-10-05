import boto3
import datetime
import json
import jwt

from datetime import datetime, timedelta
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
    
    body = json_data['body']
    body_json = json.loads(body)
    class_date = body_json['class_date']
    new_loc_id = body_json['location_id']

    #Date comes from client with time appended. Strip that off
    classDateSplit = class_date.split("/")
    classDateString = classDateSplit[0]
    print("classDateString" + classDateString)
    
    global dynamodb
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")

    orig_class_details = getClassDetails(classDateString)
    orig_capacity = orig_class_details['capacity']
    
    updateLocation(class_date, new_loc_id)
    
    new_class_details = getClassDetails(classDateString)
    new_capacity = new_class_details['capacity']
    isFree = new_class_details['isFree']
    spots_taken = new_class_details['spots_taken']
    
    print("new_capacity = " + str(new_capacity) + " orig_capacity " + str(orig_capacity))
    #Smaller class, so need to move people to waitlist and refund credits
    if(new_capacity < orig_capacity):
        moveAboveCapacityToWaitlist(class_date, new_capacity, isFree)
        
    #Bigger class, so move people off the waitlist and charge them a credit
    elif(new_capacity > orig_capacity):
        print("bigger capacity!")
        moveBelowCapacityOffWaitlist(class_date, new_capacity, isFree, spots_taken)
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps("Location Updated")
    }
    
def updateLocation(class_date, new_loc_id):
    print("in updateLocation")
    table = dynamodb.Table('HighClasses')
    
    class_date_split = class_date.split('-')
    class_year = class_date_split[0]
    
    response = table.update_item(
        Key={
            'class_year': class_year,
            'class_date': class_date
        },
        UpdateExpression='SET #location = :l',
        ExpressionAttributeNames =  {
                    '#location': 'location'
                },
        ExpressionAttributeValues={
                ':l': new_loc_id
            },
        ReturnValues="UPDATED_NEW"
    )
    print(str(response))
    
    
def moveAboveCapacityToWaitlist(class_date, capacity, isFree):
    print("in moveAboveCapacityToWaitlist")
    
    #First, look who was reserved above new capacity and credit them back
    table = dynamodb.Table('HighLiveClassSignup')
    query_response = table.query(
        KeyConditionExpression=Key('class_date').eq(class_date)
    )
    
    for i in query_response['Items']:
        dbName = i['username']
        spot_number = i['reserve_position']
        waitlist_number = i['waitlist_position']
        
        #Paid class is being made smaller, so credit users losing reserved spots
        if not isFree and (waitlist_number == 0 and spot_number > capacity):
            returnPaidCredit(dbName)
            
            #Notify user via email:
            email = getEmailForUser(dbName)
            sendWaitlistEmail(email, class_date)
            
    #Next, reorder the list
    reorderPositions(class_date, True, isFree, capacity)

def moveBelowCapacityOffWaitlist(class_date, capacity, isFree, spots_taken):
    print("in moveBelowCapacityOffWaitlist")
    
    waitlisted_peeps = []
    sorted_waitlist = []
    reserveCount = 0
    
    #Step 1, Get and sort waitlist, and determine how many reserved spots are already taken
    table = dynamodb.Table('HighLiveClassSignup')
    query_response = table.query(
        KeyConditionExpression=Key('class_date').eq(class_date)
    )
    
    for i in query_response['Items']:
        dbName = i['username']
        spot_number = i['reserve_position']
        waitlist_number = i['waitlist_position']
        
        print(dbName + " waitlist_number = " + str(waitlist_number) + " spot_number = " + str(spot_number))
        
        #Paid class is being made bigger, so charge users gaining reserved spots
        if (waitlist_number > 0 and spot_number == 0):
            data = {
            "username" : dbName,
            "waitlist_number" : waitlist_number
            }   
            waitlisted_peeps.append(data)
        elif spot_number > 0:
            reserveCount = reserveCount + 1
    
    availSpots = capacity - reserveCount
    print("availSpots = " + str(availSpots))
   
    sorted_waitlist = sorted(waitlisted_peeps, key = lambda i: i['waitlist_number'])
    
    #Step 2: Loop through sorted waitlist and charge a credit for everyone who fits in new capacity
    i = 0
    while(i < availSpots): 
        
        waitListPerson = sorted_waitlist[i]
        username = waitListPerson['username']
    
        print("moving " + username + "  in off the waitlist and charging a credit!")
        chargeCreditForBumpedUpUser(username)
            
        #Notify user via email:
        email = getEmailForUser(username)
        sendReservedEmail(email, class_date)
         
        i = i + 1
            
    #Next, reorder the list
    reorderPositions(class_date, True, isFree, capacity)

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

def reorderPositions(class_date, reserved, isFree, capacity):
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
        
        #Update resSpot for people already in the class
        if classCountIter <= capacity:
            resSpot = classCountIter
            
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
    
def getClassDetails(class_date):
    print("in getClassDetails " + class_date)
    #Step 1: Get Location
    table = dynamodb.Table('HighClasses')
    location = ''
    classDateObj = datetime.strptime(class_date, '%Y-%m-%d')
    class_year = classDateObj.strftime( "%Y")
    isFree = False
    class_time = ''
  
    response = table.query(
        KeyConditionExpression=Key('class_year').eq(class_year) & Key('class_date').eq(class_date)
    )
    
    
    for i in response['Items']:
        location = i['location']
        class_time = i['class_time']
        spots_taken = i['spots_taken']
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
        'spots_taken' : spots_taken
    }
    return data
    
    
def getEmailForUser(username):
    print("in getEmailForUser")
    table = dynamodb.Table('HighUsers')
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    for i in query_response['Items']:
        email = i['email']
        return email
        
        
def sendWaitlistEmail(email, class_date):
    print("in sendEmail")
    SENDER = "anniecassiehigh@gmail.com"
    AWS_REGION = "us-east-2"
    SUBJECT = str(class_date) + " High Class Moving to Smaller Location"
    CHARSET = "UTF-8"

    BODY_TEXT = ("High Class Moving to Smaller Location")
    BODY_HTML = """<html><head></head><body>
  <h1>""" + str(class_date) + """ High Class Moving to Smaller Location</h1>
  <p>We regret the inconvenience, but wish to notify you that the High Class scheduled for """ + str(class_date) + """ has been moved to a smaller location and you are now on the waitlist. Your class credit will be returned to your account for future use.</p>
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

def sendReservedEmail(email, class_date):
    print("in sendEmail")
    SENDER = "anniecassiehigh@gmail.com"
    AWS_REGION = "us-east-2"
    SUBJECT = str(class_date) + " You're In! High Class Moving to Larger Location"
    CHARSET = "UTF-8"

    BODY_TEXT = ("You're In! High Class Moving to Larger Location")
    BODY_HTML = """<html><head></head><body>
  <h1>""" + str(class_date) + """ You're In! High Class Moving to Larger Location</h1>
  <p>Hello! The High Class scheduled for """ + str(class_date) + """ has been moved to a larger location and you now have a reserved spot. If you can no longer make it, please cancel prior to 3 hours before class to ensure a refunded credit.</p>
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