import boto3
import json
import logging
from boto3.dynamodb.conditions import Key
from datetime import datetime
from botocore.exceptions import ClientError


logger = logging.getLogger('classcount-updater')
hdlr = logging.FileHandler('/var/log/class_count.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.DEBUG)

def main():
	global dynamodb
	global table 
	dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
	table = dynamodb.Table('SiteUsers')
	scan_response = table.scan()

	for i in scan_response['Items']:
		json_string = json.dumps(i)
		json_data = json.loads(json_string)
        
		dbUser = json_data['username']

		liveCount = getLiveCountForUser(dbUser)
		streamCount = getStreamCountForUser(dbUser)
		totalCount = liveCount + streamCount
		strTotalCount = str(totalCount)

		logger.debug("Total Count for " + dbUser + ": " + str(totalCount))

		if(totalCount > 0):
			logger.debug("Updating count for " + dbUser)
			update_response = table.update_item(
				Key={'username' : dbUser},
				UpdateExpression="set #classcount=:c",
	                ExpressionAttributeValues={
	                    ':c': strTotalCount
	                },
	                ExpressionAttributeNames =  {
	                    '#classcount': 'classcount'
	                },
	                ReturnValues="UPDATED_NEW"
	            )


def getStreamCountForUser(username):
	table = dynamodb.Table('HighStreamStats')
	query_response = table.query(
    	KeyConditionExpression=Key('username').eq(username),
    	IndexName="username-index"
	)

	streamCount = len(query_response['Items'])
	return streamCount

def getLiveCountForUser(username):
	table = dynamodb.Table('HighLiveClassSignup')
	query_response = table.query(
    	KeyConditionExpression=Key('username').eq(username),
    	IndexName="username-index"
	)

	liveCount = len(query_response['Items'])
	return liveCount


if __name__ == '__main__':
    main()