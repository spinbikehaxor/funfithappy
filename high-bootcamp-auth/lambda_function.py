import boto3
import json
import base64
import os
import time

from typing import Optional
from datetime import datetime
from datetime import timedelta

def lambda_handler(event, context):
    
    bucket_name = os.environ['bucketname']
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket_name)
    signed_urls = []

    for my_bucket_object in bucket.objects.filter(Prefix='videos/'):
        video = my_bucket_object.key
        if video == "videos/":
            continue
        print(video)
        url = generate_presigned_url(video)
        noprefix = video.split("/")[1]
        displayname = noprefix.split(".")[0]
        
        video_link = {"name": displayname, "url" : url}
        signed_urls.append(video_link)
      
    return {
        'statusCode': 200,
        'headers': 
             {
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
             },
        'body': json.dumps(signed_urls)
    }
    

def generate_presigned_url(bucket_resource_url):
    print("in generate_presigned_url")
    bucket_name = os.environ['bucketname']
    url = create_presigned_url(
        bucket_name,
        bucket_resource_url
    )
    return {
        'url': url
    }


def create_presigned_url(
        bucket_name: str, object_name: str, expiration=3600) -> Optional[str]:
    """Generate a presigned URL to share an s3 object

    Arguments:
        bucket_name {str} -- Required. s3 bucket of object to share
        object_name {str} -- Required. s3 object to share

    Keyword Arguments:
        expiration {int} -- Expiration in seconds (default: {3600})

    Returns:
        Optional[str] -- Presigned url of s3 object. If error, returns None.
    """

    # Generate a presigned URL for the S3 object
    
    s3_client = boto3.client('s3')
    a_day_in_seconds = 60*60*24
    try:
        # note that we are passing get_object as the operation to perform
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={
                                                        'Bucket': bucket_name,
                                                        'Key': object_name
                                                    },
                                                    ExpiresIn=a_day_in_seconds)
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL
    return response



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