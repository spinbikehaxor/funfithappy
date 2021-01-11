import boto3
import json
import logging
from boto3.dynamodb.conditions import Key
from datetime import datetime
from botocore.exceptions import ClientError

def main():
	global dynamodb
	dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
	makeClassFree('2021-01-02 15:35:39.794457-08:00')


def makeClassFree(class_date):
	print("in makeClassFree for " + class_date)
	class_year = class_date.split("-")[0]
	table = dynamodb.Table('HighClasses')
	query_response = table.update_item(
		Key = {
		'class_year' : class_year,
		'class_date' : class_date
		},
		UpdateExpression="set isFree=:t",
		ExpressionAttributeValues={
			':t': 'True'
		}
	)
	print("makeClassFree, updated HighClasses" + str(query_response))
	refundReservedUsers(class_date)

def refundReservedUsers(class_date):
	print("in refundReservedUsers for " + class_date)
	table = dynamodb.Table('HighLiveClassSignup')
	query_response = table.query(
		KeyConditionExpression=Key('class_date').eq(class_date)
	)

	#Iterate through people signed up and refund a credit to anyone with a reserved spot
	for i in query_response['Items']:
		dbName = i['username']
		spotNum = i['reserve_position']
		if spotNum > 0:
			returnPaidCredit(dbName)


def returnPaidCredit(username):
	print("in returnPaidCredit for " + username)
	table = dynamodb.Table('HighLiveCredits')
	response = table.update_item(
		Key={
			'username': username
		},
		UpdateExpression='SET credits = if_not_exists(credits, :zero) + :incr',
		   # ConditionExpression="credits > :zero",
			ExpressionAttributeValues={
				':incr': 1, ':zero': 0
			},
		ReturnValues="UPDATED_NEW"
	)    

if __name__ == '__main__':
	main()