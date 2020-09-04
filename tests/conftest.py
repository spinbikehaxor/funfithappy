import os
import boto3
import moto 
import pytest

from moto.dynamodb2 import dynamodb_backend2
from moto.dynamodb2 import mock_dynamodb2


@pytest.fixture(scope='function')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'

@pytest.fixture(scope='function')
@mock_dynamodb2
def dynamodb(aws_credentials):
    yield boto3.resource('dynamodb', region_name='us-east-2')

@pytest.fixture(scope='function', autouse=True)
@mock_dynamodb2
def dynamodb_classes_table(dynamodb):
        table = dynamodb.create_table(
        TableName='HighClasses2',
        KeySchema=[
            {
                'AttributeName': 'class_year',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'class_date',
                'KeyType': 'RANGE'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'class_year',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'class_date',
                'AttributeType': 'S'
            }#,
         #   {
         #       'AttributeName': 'class_time',
        #        'AttributeType': 'S'
        #    },
         #   {
          #      'AttributeName': 'location',
          #      'AttributeType': 'S'
          #  },
          #  {
          #      'AttributeName': 'spots_taken',
          #      'AttributeType': 'N'
          #  },
          #  {
          #      'AttributeName': 'isFree',
          #      'AttributeType': 'S'
          #  },
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 1,
            'WriteCapacityUnits': 1
        })

        table.meta.client.get_waiter('table_exists').wait(TableName='HighClasses2')

        with open("HighClasses.json") as json_file:
            classes = json.load(json_file)
            
            for high_class in classes:
                    year = high_class['class_year']
                    class_date = high_class['class_date']
                    print(high_class)

                    response = dynamodb_classes_table.put_item(
                        Item=
                        {
                          'class_year': year,
                          'class_date': class_date,
                          'class_time': high_class['class_time'],
                          'location' : high_class['location'],
                          'spots_taken': high_class['spots_taken'],
                          'isFree': high_class['isFree']
                        }
                        )


        yield
        #yield boto3.resource('dynamodb').Table("HighClasses2")