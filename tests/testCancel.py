import boto3
import json
import os
import pytest

from moto import mock_dynamodb2
from boto3.dynamodb.conditions import Key

class TestCancellations:

    def testClasses(self, dynamodb_classes_table):

        table = setupClasses()


        #print(str(dynamodb_classes_table))
        query_response = table.query(
         KeyConditionExpression=Key('class_year').eq('2021')
        )

    def setupClasses():
        mock = mock_dynamodb2()
        mock.start()

        global dynamodb
        dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")


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
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 1,
            'WriteCapacityUnits': 1
        })

        with open("HighClasses.json") as json_file:
            classes = json.load(json_file)
            
            for high_class in classes:
                    year = high_class['class_year']
                    class_date = high_class['class_date']
                    print(high_class)

                    response = table.put_item(
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
        return table
            
      