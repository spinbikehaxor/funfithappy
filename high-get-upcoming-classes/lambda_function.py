import boto3
import datetime
import json
import jwt
import pytz
import time

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from dateutil import parser
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
    
    global dynamodb
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    
    classlist = getClasses(isLoggedIn(headers))
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': classlist
    }
    
def isLoggedIn(headers):
    isLoggedIn = True
    
    if 'x-api-key' not in headers.keys():
        isLoggedIn = False
    else:
        authHeader = headers['x-api-key']
        if not authHeader or authHeader == 'null':
            isLoggedIn = False
            
        else:
            if not isAuthorized(authHeader):
                print("not authorized")
                isLoggedIn = False
    
    return isLoggedIn

def getClasses(isLoggedIn):
    table = dynamodb.Table('HighClasses')
    location = ''
    future_classes = []
    current_year = getCurrentTimePacific().strftime( "%Y")
    current_date = getCurrentTimePacific().strftime( "%Y-%m-%d")
    resSpot = 0
    waitSpot = 0
    isFree = False
    class_type = "High"
    isComboInList = False
    comboDate = ""
    info = ""
    
    #TODO: Adjust for timezone
    scan_response = table.scan(
        FilterExpression=Attr('class_date').gte(current_date)
    )

    for i in scan_response['Items']:
        
        #Skip any records that aren't ready for posting
        post_date = i['post_date']
        post_time = i['post_time']
        if not isReadyToDisplay(post_date, post_time): 
            continue
        
        #Skip any records for the same day where the time has past
        class_date = i['class_date']
        class_time = i['class_time']
        
        if not isBeforeClassTime(class_date, class_time):
            continue
        
        isFree = False
        reserved = None
        class_type = "High"
        
        if " " in class_date:
            class_date_split = class_date.split(" ")
            class_date = class_date_split[0]
            
        if isLoggedIn:
            user_class_list = getUserClasses()
            reservedClass = next((item for item in user_class_list if item["class_date"] == i['class_date']), None)
        
            if reservedClass:
                print("found class " + str(class_date) + " for user " + username)
                reserved = "reserved"
                resSpot = reservedClass['reserve_position']
                waitSpot = reservedClass['waitlist_position']
                if(resSpot == '0'):
                    if(waitSpot > '0'):
                        reserved = "waitlisted"
            
        t = time.strptime(class_time, "%H:%M")
        timevalue_12hour = time.strftime( "%-I:%M %p", t )
        
        if 'isFree' in i.keys():
            print("db value of isFree for class " + class_date + " is " + i['isFree'] )
            isFree = i['isFree']
            
        if 'class_type' in i.keys():
            class_type = i['class_type']
            
            if class_type == "Boot-Low Combo":
                isComboInList = True
                comboDate = class_date
        
        if "info" in i.keys():
            info = i['info']
        
        spots_taken = 0
        location_data = getLocationDetails(i['location'])
            
        if 'spots_taken' in i.keys():
            spots_taken= i['spots_taken']
        class_data = {
            "class_date":class_date,
            "class_time":timevalue_12hour,
            "reserved":reserved,
            "spots_taken":str(spots_taken),
            "res_spot": resSpot,
            "waitSpot": waitSpot,
            "isFree": isFree,
            "class_type" : class_type,
            "info": info
        }
            
        class_data.update(location_data)
        future_classes.append(class_data)

    sorted_classes = sorted(future_classes, key = lambda i: i['class_date'])
    
    #If there is a combo class, hide/display the combo and indiv classes based on prior signups. Prevent dup signups!
    if isComboInList:
        sorted_classes = updateListForCombos(sorted_classes, comboDate)
        
    return json.dumps(sorted_classes)
    
#Loop through classes one more time. If signed up for combo, hide the indiv classes and vice versa
def updateListForCombos(sorted_classes, comboDate):
    
    updatedClassList = []
    
    #Strip off the timestamp
    comboDateStrip = comboDate.split(" ")[0]
    
    #reservedClass =   next((item for item in user_class_list if item["class_date"] == i['class_date']), None)
    
    isComboReserved = next((item for item in sorted_classes if 
        item["class_date"].split(" ")[0] == comboDateStrip and 
        item['class_type'] == "Boot-Low Combo" and 
        item['reserved'] in ('reserved', 'waitlisted')), None)
    
    isBootReserved = next((item for item in sorted_classes if 
        item["class_date"].split(" ")[0] == comboDateStrip and 
        item['class_type'] == "Boot Camp" and
        item['reserved'] in ('reserved', 'waitlisted')), None)
        
    isLowReserved = next((item for item in sorted_classes if 
        item["class_date"].split(" ")[0] == comboDateStrip and 
        item['class_type'] == "High-Low" and
        item['reserved'] in ('reserved', 'waitlisted')), None)
    
    for i in sorted_classes:
        class_type = i['class_type']
        class_date = i['class_date']
        reserved = i['reserved']
    
        classDateStrip = class_date.split(" ")[0]
        if(classDateStrip == comboDateStrip):
            
            #Don't add to list if signed up for combo
            if isComboReserved:
                if class_type == "Boot Camp" or class_type == "High-Low": 
                    continue;
            elif isBootReserved or isLowReserved:
                if class_type == "Boot-Low Combo":
                    continue;
            
        #Add everything else to the class list
        updatedClassList.append(i)
    return updatedClassList
    
def isReadyToDisplay(post_date, post_time):
    post_timestamp_string = str(post_date) + " " + str(post_time)
    post_datetime = parser.parse(post_timestamp_string)
    post_datetime_pacific = timezone('US/Pacific').localize(post_datetime)
    print("post_datetime_pacific: " + str(post_datetime_pacific))

    currentTimePacific = getCurrentTimePacific()
    print("currentTimePacific: " + str(currentTimePacific))

    if currentTimePacific < post_datetime_pacific: 
        print("not ready to post!")
        return False
    else:
        print("ready to post!")
        return True
        
        
def isBeforeClassTime(class_date, class_time):
    class_timestamp_string = str(class_date) + " " + str(class_time)
    class_datetime_pacific = parser.parse(class_timestamp_string)
    print("class_datetime_pacific: " + str(class_datetime_pacific))
    
    currentTimePacific = getCurrentTimePacific()
    print("currentTimePacific: " + str(currentTimePacific))

    if currentTimePacific > class_datetime_pacific: 
        print("class has already started!")
        return False
    else:
        print("class hasn't happened yet")
        return True
        
def getCurrentTimePacific():
    utcmoment_naive = datetime.utcnow()
    utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
    currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
    return currentTimePacific
    
def getLocationDetails(location):
    table = dynamodb.Table('HighLocation')
    location_data = {}
  
    response = table.query(
        KeyConditionExpression=Key('name').eq(location)
    )

    for i in response['Items']:
        capacity = str(i['capacity'])
        display_name = i['display_name']
        address = i['address']
        
        location_data = {
            "capacity":capacity,
            "display_name": display_name,
            "address":address
        }
    return location_data
    
def getUserClasses():
    table = dynamodb.Table('HighLiveClassSignup')
    userformatted = username.lower().strip()
    current_date = datetime.now().strftime( "%Y-%m-%d")
    user_class_list = []
    
    scan_response = table.scan(
        FilterExpression=Key('username').eq(userformatted) & Key('class_date').gte(current_date)
    )
    
    for i in scan_response['Items']:
  
        
        data = {
            'class_date' : i['class_date'],
            'reserve_position': str(i['reserve_position']),
            'waitlist_position': str(i['waitlist_position'])
        }
        user_class_list.append(data)
    print(str(user_class_list))
    return user_class_list
    
    
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