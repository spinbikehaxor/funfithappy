import boto3
import datetime
import json
from datetime import datetime

def lambda_handler(event, context):
    
    activeStreamTime = False
    streamMorningDays = ['Tuesday', 'Thursday', 'Sunday']
    #streamMorningDays = ['Tuesday', 'Thursday', 'Saturday', 'Sunday']
    #streamEveningDays = ['Tuesday', 'Wednesday', 'Thursday', 'Sunday']
    
    streamEveningDays = ['Wednesday', 'Friday']
    streamMorningHour = "17"
    #streamMorningHour = "11"
    streamEveningHour = "01" 
    
    #streamEveningHour = "00" 
    #streamMorningHour = "12" 
    
    todayDayOfWeek = datetime.now().strftime("%A")
    todayHour = datetime.now().strftime( "%H")
    print(todayDayOfWeek)
    print(todayHour)
    
    
    if(str(todayDayOfWeek) in streamMorningDays and todayHour == streamMorningHour):
        print("Yay it's a stream day!")
        activeStreamTime = True
    elif(str(todayDayOfWeek) in streamEveningDays and todayHour == streamEveningHour):
        print("Yay it's an evening stream day!")
        activeStreamTime = True
        
    if activeStreamTime:
        global dynamodb 
        dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
        table = dynamodb.Table('HighVideoLink')
        scan_response = table.scan();
        
        for i in scan_response['Items']:
            json_string = json.dumps(i)
            json_data = json.loads(json_string)
            
            url = json_data['url']
            body = {"url" : url}
        
        print(str(scan_response))
        return {
            'statusCode': 200,
            'headers': 
                 {
                    'Access-Control-Allow-Headers': '*',
                    'Access-Control-Allow-Origin':  '*',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
                 },
            'body': json.dumps(body)
        }
   
    return {
    'statusCode': 200,
    'headers': 
         {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
         },
    'body': json.dumps("No Active Stream at this Time")
    }

