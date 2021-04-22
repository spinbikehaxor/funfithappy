import boto3
import html
import json
import requests
from botocore.exceptions import ClientError
from email_validator import validate_email, EmailNotValidError

def lambda_handler(event, context):
    json_string = json.dumps(event)
    json_data = json.loads(json_string)
    body = json.loads(json_data['body'])
    
    captcha = body['captcha']
    
    if not isValidCaptcha(captcha):
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("Captcha Challenge Failed")
        }
    
    name = html.escape(body['name'])
    email = html.escape(body['email'])
    message = html.escape(body['message'])

    try:
        valid = validate_email(email)
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

    sendEmail(name, email, message)
    
    return {
       'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps('Email sent!')
    }

def isValidCaptcha(captcha):
    print("in validateCaptcha")
    
    #Call Google to verify captcha
    url = "https://www.google.com/recaptcha/api/siteverify"
    
    secretString = json.dumps(get_secret('captcha_secret'))
    secretData = json.loads(secretString)
    CAPTCHA_SECRET = secretData['captcha']
    data = {
        'secret' : CAPTCHA_SECRET,
        'response' : captcha
    }

    r= requests.post(url, data)
    response_json = json.loads(r.text)
    if(response_json['success'] is False):
        print("Captcha failed: " + str(response_json['error-codes']))
        return False
    print("captcha results " + str(response_json))
    return True

def sendEmail(name, email, message):
    print("in sendEmail")
    SENDER = "dwongfitness@gmail.com"
    AWS_REGION = "us-east-2"
    SUBJECT = "Contact Us Inquiry"
    CHARSET = "UTF-8"

    BODY_TEXT = ("Contact Us Inquiry From " + name)
    BODY_HTML = """<html><head></head><body>
  <h1>Contact Us Inquiry from """ + name + """</h1>
  <p>""" + message + """</p> 
  <p>User may be contacted at """ + email + """</p>
</body></html>
 """
    email = ["dwongfitness@gmail.com", "funfithappy.ca@gmail.com"]
    client = boto3.client('ses',region_name=AWS_REGION)


    try:
    #Provide the contents of the email.
        print("sending email to " + str(email))
        response = client.send_email(
            Destination={
                'ToAddresses': 
                     email
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