import base64
import boto3
import datetime
import json
import jwt
import time
from datetime import datetime
from boto3.dynamodb.conditions import Key

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
            
            if username not in ('dianatest', 'casshighfit', 'anniesouter'):
                print("User is not an admin")
                return False
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
    json_string = json.dumps(event)
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
    
    global dynamodb 
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    
    locations = getLocations()
    classes = getUpcomingClasses()
    streamingTimes = getStreamingTimes()
    
    print(str(locations))
    print(str(classes))
    print(str(streamingTimes))
    
    data = {
        'locations':locations,
        'classes' : classes,
        "streamingTimes" : streamingTimes
    }
    
    return {
        'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps(data)
    }
    
def getUpcomingClasses():
    table = dynamodb.Table('HighClasses')
    location = ''
    future_classes = []
    sorted_classes = []
    current_year = datetime.now().strftime( "%Y")
    current_date = datetime.now().strftime( "%Y-%m-%d")
    
    #TODO: Adjust for timezone
    query_response = table.query(
        KeyConditionExpression=Key('class_year').eq(current_year) & Key('class_date').gte(current_date)
    )

    for i in query_response['Items']:
        
        class_date = i['class_date']
        class_time = i['class_time']
        t = time.strptime(class_time, "%H:%M")
        timevalue_12hour = time.strftime( "%-I:%M %p", t )
        roster = getClassRoster(class_date)
        
        data = {
            'class_date' : class_date,
            'class_time' : timevalue_12hour,
            'location' : i['location'],
            'spots_taken': str(i['spots_taken']),
            'roster' : roster
        }
       
        future_classes.append(data)
    sorted_classes = sorted(future_classes, key = lambda i: i['class_date'])
    return sorted_classes
    
def getClassRoster(classdate):
    table = dynamodb.Table('HighLiveClassSignup')
    query_response = table.query(
        KeyConditionExpression=Key('class_date').eq(classdate)
    )
    roster = []
    sorted_roster = []
    
    for i in query_response['Items']:
        username = i['username']
        spot_number = i['reserve_position']
        waitlist_number = i['waitlist_position']
        signup_time = i['signup_time']
        realname = getAttendeeName(username)
        
        data = {
            'username' : realname,
            'spot_number' : str(spot_number),
            'waitlist_number' : str(waitlist_number),
            'signup_time' : signup_time
        }
        roster.append(data)
    sorted_roster = sorted(roster, key = lambda i: i['signup_time'])
    return sorted_roster
    
def getAttendeeName(username):
    table = dynamodb.Table('SiteUsers')
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    for i in query_response['Items']:
        fname = i['fname']
        lname = i['lname']
        
        fullname = fname + " " + lname
        return fullname
    
def getStreamingTimes():
    table = dynamodb.Table('HighStreamingTimes')
    scan_response = table.scan()
    times = []
    sorted_times = []
    sorter = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    sorterIndex = dict(zip(sorter,range(len(sorter))))
    
    for i in scan_response['Items']:
        dayOfWeek = i['day_of_week']
        dayOfWeekNum = getDayOfWeek(dayOfWeek)
        timeOfDay = i['time_of_day']
        data = {
            'dayOfWeek' : dayOfWeek,
            'timeOfDay': timeOfDay,
            'dayOfWeekNum' : dayOfWeekNum
        }
        times.append(data)
    sorted_times = sorted(times, key = lambda i: i['dayOfWeekNum'])
    return sorted_times
    
def getDayOfWeek(dayName):
    switcher = {
        "Sunday"    : 0,
        "Monday"    : 1,
        "Tuesday"   : 2,
        "Wednesday" : 3,
        "Thursday"  : 4,
        "Friday"    : 5,
        "Saturday"  : 6
    } 
    return switcher.get(dayName)   
    
def getLocations():
    print('in getLocations')
   
    table = dynamodb.Table('HighLocation')
    scan_response = table.scan();
    locations = []
    sorted_locations = []
    
    for i in scan_response['Items']:

        data = {
            'locId' : i['name'],
            'address': i['address'],
            'capacity' : str(i['capacity']),
            'display_name' : i['display_name']
        }
    
        locations.append(data)
    
    sorted_locations = sorted(locations, key = lambda i: i['locId'])
    return sorted_locations
        


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