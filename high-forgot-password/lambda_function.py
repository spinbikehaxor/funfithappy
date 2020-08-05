import boto3
from botocore.exceptions import ClientError
import datetime
import json
from datetime import datetime, timedelta

def lambda_handler(event, context):
    print('in HighForgotPassword lambda_handler')
    
    SENDER = "anniecassiehigh@gmail.com"
    AWS_REGION = "us-east-2"
    SUBJECT = "Password Reset: Annie Cassie Fit"
    CHARSET = "UTF-8"
    
    json_string = json.dumps(event)
    json_data = json.loads(json_string)
    body = json.loads(json_data['body'])
    
    email = body['email']
    client = boto3.client('ses',region_name=AWS_REGION)
    token = createJWT(email);
    print(token);
    

    BODY_TEXT = ("A request was submitted to reset your Annie Cassie Fit password. If you submitted this request, please click the provided link to reset your password.")
    BODY_HTML = """<html><head></head><body>
  <h1>Password Reset: Annie Cassie Fit</h1>
  <p>"A request was submitted to reset your Annie Cassie Fit password. If you submitted this request, please click the provided link to reset your password</a>."</p>
</body></html>
 """ 

    try:
    #Provide the contents of the email.
        response = client.send_email(
            Destination={
                'ToAddresses': [
                    email,
                ],
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
        'body': json.dumps('Hello from Lambda!')
    }

def createJWT(email):
    secretString = json.dumps(get_secret('jwt-secret'))
    secretData = json.loads(secretString)
    JWT_SECRET = secretData['jwt-secret']

    JWT_ALGORITHM = 'HS256'
    JWT_EXP_DELTA_SECONDS = 60*60*.3 #20 minute token

    payload = {
        'email': email,
        'exp': datetime.now() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
    return json.dumps({'token': jwt_token.decode('utf-8')})
    
    
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