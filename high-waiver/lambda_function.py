import boto3
import html
import json
import jwt
import phonenumbers
from botocore.exceptions import ClientError
from datetime import datetime
from email_validator import validate_email, EmailNotValidError

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
    print("headers: " + str(headers))
    
    if 'x-api-key' not in headers.keys():
        print("no token found - returning a 401")
        return {
            'statusCode': 401,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("Please sign in before submitting the waiver")
        }
    else:
        print("got api key!")
        authHeader = headers['x-api-key']
        
    if not isAuthorized(authHeader):
        return 
        {
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
    print(str(body))
    
    isValidPhone = False
    try:
        formattedPhone = phonenumbers.parse(body['phone'], "US")
        isValidPhone = phonenumbers.is_valid_number(formattedPhone)
    except:
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("The phone number entered appears invalid")
        }
    if not isValidPhone:
        print("invalid phone")
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("The phone number entered appears invalid")
        }

    #Validate email
    try:
        valid = validate_email(body['email'])
    except EmailNotValidError as e:
        # email is not valid, exception message is human-readable
        print(str(e))
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("The email entered appears invalid")
        }

    if not body['street'] or not body['state'] or not body['zip'] or not body['esig'] or not body['print-name']:
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("All fields are required. Please enter missing information.")
        }
    
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighWaivers')
    
    response = table.put_item(
        Item={
            'username': username,
            'email': html.escape(body['email']),
            'fname': html.escape(body['fname']),
            'lname' : html.escape(body['lname']),
            'street' : html.escape(body['street']),
            'city' : html.escape(body['city']),
            'state' : html.escape(body['state']),
            'zip' : html.escape(body['zip']),
            'phone': html.escape(body['phone']),
            'optIntoPromo': False,
            'esig' : html.escape(body['esig']),
            'print-name' : html.escape(body['print-name']),
            'date-signed' : str(datetime.now())
        }
    )
        
    print(response)
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps('Waiver written to DynamoDB!')
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
