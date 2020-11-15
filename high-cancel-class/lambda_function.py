import base64
import boto3
import datetime
import html
import json
import jwt
import time
from botocore.exceptions import ClientError
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr

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
    
    body = json.loads(json_data['body'])
    deleteClass(body)
        
    return {
        'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps('Class Cancelled')
    }
    
def deleteClass(body):
    global dynamodb
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighClasses')
    
    class_date = html.escape(body['class_date'].lower().strip())
    class_type = html.escape(body['class_type'].strip())
    class_year_split = class_date.split('-')
    class_year = class_year_split[0]
    
    class_details = getClassDetails(class_date, class_type)
    class_key = class_details['class_date']
    isFree = class_details['isFree']
    
    response = table.delete_item(
        Key={
            'class_year': class_year,
            'class_date': class_key
        }
    )
    deleteAndCreditReservations(class_key, isFree)

    
def getClassDetails(class_date, class_type):
    print("in getClassDetails " + class_date + " " + class_type)
    #Step 1: Get Location
    table = dynamodb.Table('HighClasses')
    location = ''
    class_date_split = class_date.split("-")
    class_year = class_date_split[0]
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
    
def deleteAndCreditReservations(class_date, isFree):
    print("in deleteAndCreditReservations")
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighLiveClassSignup')
    
    query_response = table.query(
        KeyConditionExpression=Key('class_date').eq(class_date)
    )
    
    for i in query_response['Items']:
        username = i['username']
        spot_number = i['reserve_position']
        waitlist_number = i['waitlist_position']
        
        #Paid class is being cancelled, so credit users with reserved spots
        if not isFree and (spot_number > 0 and waitlist_number == 0):
            returnPaidCredit(username)
            
        #Notify User
        email = getEmailForUser(username)
        sendEmail(email, class_date)
        
        #Delete reservation
        response = table.delete_item(
            Key={
                'username': username,
                'class_date': class_date
            }
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
    
def getEmailForUser(username):
    print("in getEmailForUser")
    table = dynamodb.Table('SiteUsers')
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    for i in query_response['Items']:
        email = i['email']
        return email
        
        
def sendEmail(email, class_date):
    print("in sendEmail")
    SENDER = "anniecassiehigh@gmail.com"
    AWS_REGION = "us-east-2"
    SUBJECT = str(class_date) + " High Class Cancelled"
    CHARSET = "UTF-8"

    BODY_TEXT = ("High Class Cancelled")
    BODY_HTML = """<html><head></head><body>
  <h1>""" + str(class_date) + """ High Class Cancelled</h1>
  <p>We regret the inconvenience, but wish to notify you that the High Class previously scheduled for """ + str(class_date) + """ has been cancelled. Your class credit will be returned to your account for future use.</p>
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
        'body': json.dumps('Contact Us Email Sent!')
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