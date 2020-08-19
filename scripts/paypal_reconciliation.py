import boto3
import json
import logging
import requests
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError


logger = logging.getLogger('paypal-reconcile')
hdlr = logging.FileHandler('/var/log/paypal-reconcile.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)


def main():
    logger.info("**************************************************************************")
    logger.info("")
    logger.info("Starting reconciliation")

    authtoken = login_to_paypal()
    logger.debug("got token - ready to go!")
    reconcileSubscriptions(authtoken)

def reconcileSubscriptions(authtoken):
    global dynamodb
    global table 
    
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighPayment')
    scan_response = table.scan()


    for i in scan_response['Items']:
        #Retrieve local payment data
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        
        dbUser = json_data['username']
        logger.debug("fetching subscription for " + dbUser)
        transaction_date = json_data['transaction-date']
        subscription_id = json_data['paypal_subscription_id']
        next_billing_time = json_data['next_billing_time']
        dbStatus = json_data['status']


        #Call PayPal to reconcile database data
        url = "https://api.paypal.com/v1/billing/subscriptions/" + subscription_id
        headers = {'Content-Type': 'application/json', 'Authorization': authtoken }
        
        r= requests.get(url, headers=headers)
        response_json = json.loads(r.text)

        paypal_status = response_json['status']
        if(dbStatus != paypal_status):
            logger.info("Status is different! Local status = " + dbStatus + " paypal_status = " + paypal_status )
            if(paypal_status == 'CANCELLED'):
                logger.info(dbUser + " has canceled")
                updateLocalRecord(dbUser, transaction_date, paypal_status, None)

        if 'billing_info' not in response_json.keys():
            logger.debug("no billing info found " + str(response_json))
            continue
    
        billing_string = json.dumps(response_json['billing_info'])
        billing_data = json.loads(billing_string)


        if 'next_billing_time' not in billing_data.keys():
            logger.debug("Looks like an inactive subscription " + paypal_status)
            continue

        paypal_next_billing_time = billing_data['next_billing_time']
        logger.debug("paypal_next_billing_time = " + str(paypal_next_billing_time))

        if( (dbStatus != paypal_status) or (next_billing_time != paypal_next_billing_time)  ):
            logger.info("data mismatch for user " + dbUser)
            logger.info("Local status = " + dbStatus + " paypal_status = " + paypal_status )
            logger.info("Local billing = " + next_billing_time + " paypal billing = " + paypal_next_billing_time )
            updateLocalRecord(dbUser, transaction_date, paypal_status, paypal_next_billing_time)


def updateLocalRecord(username, transaction_date, status, next_billing_time):
    logger.info("in updateLocalRecord for user " + username )

    #This is a hack :P Paypal puts a T between the data and time and my code looks for it if there's a record.
    if not next_billing_time:
        next_billing_time = "1900-01-01T"

    update_response = table.update_item(
                Key={
                'username': username,
               'transaction-date': transaction_date
                },
               UpdateExpression="set #status=:s, next_billing_time=:n",
                ExpressionAttributeValues={
                    ':s': status,
                    ':n': next_billing_time
                },
                ExpressionAttributeNames =  {
                    '#status': 'status'
                },
                ReturnValues="UPDATED_NEW"
            )
    logger.info("Update complete! " + str(update_response))


def login_to_paypal():
    logger.info('in login_to_paypal')
    paypal_client_id = "ARFAJ4v0DMU0-jp__jkVEVNYP139DlETKokloLrUywQ0qjlOs0H5x1ETIVDJARd3rBuCPJHGKWrdZ2fY"
    
    secretString = json.dumps(get_secret('PaypalSecret'))
    secretData = json.loads(secretString)
    paypalSecret = secretData['PaypalSecret']
    
    url = "https://api.paypal.com/v1/oauth2/token"
    payload= {'grant_type': 'client_credentials'}

    r= requests.post(url, payload, auth=HTTPBasicAuth(paypal_client_id, paypalSecret))
    response_dict = r.text
    json_data = json.loads(response_dict)
    token = json_data['access_token']

    auth_token_param = "Bearer " + token
    return auth_token_param
    
def get_secret(secret_name):
    logger.info("in get_secret")
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
        logger.debug("about to retrieve value")
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        logger.error("error retrieving secret " + str(e))
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
            logger.debug("returning secret")
            return json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            logger.debug("returning secret")
            return json.loads(decoded_binary_secret)


if __name__ == '__main__':
    main()