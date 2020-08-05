import boto3
import json
from datetime import datetime
from datetime import timedelta

from botocore.exceptions import ClientError
from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def lambda_handler(event, context):
    generate_presigned_url()
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
    
def generate_presigned_url():
    expire_date = datetime.utcnow() + timedelta(days=2) # expires in 2 days
    bucket_resource_url = 'Jul-18.mp4'
    url = create_cloudfront_signed_url(
        bucket_resource_url,
        expire_date
    )
    return {
        'url': url
    }

def rsa_signer(message: str) -> str:
    # cloudfront-pk.pem is the private key generated in step 1 for IAM user
    print("in rsa_signer")
    
    cfPrivateKey = get_secret("CloudFrontPrivateKey")
   # secretData = json.loads(cfPrivateKey)
    secret = cfPrivateKey['CloudFrontPrivateKey']
    print("secret = " + secret)
    
    
    private_key = serialization.load_pem_private_key(
        secret,
        password=None,
        backend=default_backend()
    )
    print(str(private_key))
    return private_key.sign(
        message, padding.PKCS1v15(), hashes.SHA1())


def create_cloudfront_signed_url(
    object_name: str, expiration_date: datetime) -> str:
        
    print("in create_cloudfront_signed_url")
    # cloudfront key-par access ID generated in step 1
    key_id = 'APKAJMWBTJO7RXGZADZQ'
    # your cloudfront distribution domain created in step 4 of distribution creation steps
    cloudfront_domain = 'https://dy8aa08hlcmj5.cloudfront.net'

    cfurl = '{cloudfront_domain}/{object_name}'.format(
        cloudfront_domain=cloudfront_domain,
        object_name=object_name
    )
    print("url = " + str(cfurl))
    print("expiration_date = " + str(expiration_date))

    cloudfront_signer = CloudFrontSigner(key_id, rsa_signer)
    
    print("about to generate signed url - wheee!")
    # Create a signed url that will be valid until the specfic expiry date
    # provided using a canned policy.
    signed_url = cloudfront_signer.generate_presigned_url(
        url=cfurl, date_less_than=expiration_date, policy=None)
    return signed_url
    
    
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