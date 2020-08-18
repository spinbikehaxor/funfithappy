import base64
import boto3
import datetime
import json
import jwt

from datetime import datetime
from dateutil.relativedelta import relativedelta


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
    usernameformatted = username.lower().strip()
    body = json.loads(json_data['body'])
    
    print("keys = " + str(body.keys()))

   # if 'payer' not in body.keys():
    if 'subscriptionID' not in body.keys():
        print("No Transaction Details Received!")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps('No Transaction Details Received!')
        }
    else:
        
        paypal_order_id = body['orderID'] 
        paypal_subscription_id = body['subscriptionID']
        transaction_date = str(datetime.now())
        
        #Code for a single transaction
        #paypal_transaction_id = body['id']
        #paypal_transaction_status = body['status']
        #transaction_date = body['update_time']

        #Get PayPal PayerID
        #payer_string = json.dumps(body['payer'])
        #payer_data = json.loads(payer_string)
        #paypal_payer_id = payer_data['payer_id']
        
        #Get Transaction Amount
        #purchase_string = json.dumps(body['purchase_units'])
        #purchase_data = json.loads(purchase_string)
        #amount = purchase_data[0]['amount']
        #amount_string = json.dumps(amount)
        #amount_data = json.loads(amount_string)
        #amount_paid = amount_data['value']
        #print("amount_paid " + amount_paid)
        
        dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
        table = dynamodb.Table('HighPayment')
        
        next_billing_date = datetime.today()+ relativedelta(months=1)
        next_billing_date_string = str(next_billing_date)
        next_billing_date_split = next_billing_date_string.split(" ")
        next_billing_date_prefix = next_billing_date_split[0]
        next_billing_date_paypal_mimic = next_billing_date_prefix + "T"
        
        #nextBillingDateString = datetime.strptime(str(next_billing_date), '%Y-%m-%d')
        print(next_billing_date_paypal_mimic)
        
        response = table.put_item(
            Item={
                'transaction-date': transaction_date,
                'username': usernameformatted,
                'paypal_subscription_id': paypal_subscription_id,
                'paypal_order_id' : paypal_order_id,
                'status': 'ACTIVE',
                'next_billing_time': str(next_billing_date_paypal_mimic)
                
       #         'paypal-transaction-status': paypal_transaction_status,
      #          'amount-paid': amount_paid,
       #         'paypal-details': body
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
            'body': json.dumps('Transaction written to DynamoDB!')
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
    

