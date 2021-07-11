import boto3
import json

global dynamodb
dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
table = dynamodb.Table('SiteUsers')

scan_response = table.scan();
emaillist = ""
    
 #iterate and run the process for each user
for i in scan_response['Items']:
    json_string = json.dumps(i)
    json_data = json.loads(json_string)
    
    dbUser = json_data['username']
    email = json_data['email']

    emaillist += email 
    emaillist +=","
    
print(emaillist)