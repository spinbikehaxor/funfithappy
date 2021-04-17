import boto3
import datetime
import json
import jwt

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime, timedelta


def lambda_handler(event, context):
    json_string = json.dumps(event)
    print("in lambda_handler - " + json_string)
    json_data = json.loads(json_string)
    
    global dynamodb 
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    
    username = json_data['username']
    promo_id = json_data['promo_id']
    details = get_promo_details(promo_id)
    if(details['active'] == False):
        return {
        'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps('Promo is not active, no action taken')
        }
    if(details['type'] == "live"):
        applyLivePromo(promo_id, details['amount'], username)
    

def get_promo_details(promo_id):
    table = dynamodb.Table('HighPromo')
    query_response = table.query(
        KeyConditionExpression=Key('promo_id').eq(promo_id)
    )
    data = {
        'amount' : query_response['Items'][0]['amount'],
        'type'   : query_response['Items'][0]['type'],
        'active' : query_response['Items'][0]['active']
    }
    print(str(data))
    return data
    
def applyLivePromo(promo_id, amount, username):
    print('in applyLivePromo')
    numClasses = int(int(amount)/10)
    credits = numClasses
    print("number of live classes: " + str(numClasses))
    
    #First, write to Promo Credit table to differentiate from a purchased credit
    table = dynamodb.Table('HighPromoCredit')
    response = table.put_item(
        Item={
            'username': username,
            'transaction_date' : str(datetime.now()),
            'promo_id': promo_id,
            'applied_live': True
        }
    )
    
    #Next, write to Live Credit table so they can actually sign up for classes
    table = dynamodb.Table('HighLiveCredits')
    
    #Check for existing credits - if there, just update
    query_response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    
    for i in query_response['Items']:
        dbCredits = i['credits']
        credits = (numClasses + dbCredits)
        print("added credits to existing amount")
        
    response = table.put_item(
            Item={
                'username': username,
                'credits' : credits,
                'update_time': str(datetime.now())
            }
        )
    
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