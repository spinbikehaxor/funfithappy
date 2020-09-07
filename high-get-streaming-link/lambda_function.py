import boto3
import datetime
import json
import pytz


from datetime import datetime, timedelta
from boto3.dynamodb.conditions import Key
from pytz import timezone

def lambda_handler(event, context):
    global dynamodb 
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    
    if withinStreamingWindow():
       
        table = dynamodb.Table('HighVideoLink')
        query_response = table.query(
        KeyConditionExpression=Key('classname').eq('high')
        )

        for i in query_response['Items']:
            json_string = json.dumps(i)
            json_data = json.loads(json_string)
            
            url = json_data['url']
            body = {"url" : url}
        
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

def withinStreamingWindow():
    print("in withinStreamingWindow")
    #Get the current time in the Pacific Time Zone
    utcmoment_naive = datetime.utcnow()
    utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
    currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
    todayDayOfWeek = currentTimePacific.strftime("%A")

    #Get datetime again but this time for the stream - will update shortly
    stream_naive = datetime.utcnow()
    stream_moment = stream_naive.replace(tzinfo=pytz.utc)
    streamStartTime = stream_moment.astimezone(timezone('US/Pacific'))

    print("Looking up times for " + todayDayOfWeek)
    #Pull streaming times for the current day (if any)
    table = dynamodb.Table('HighStreamingTimes')
    query_response = table.query(
        KeyConditionExpression=Key('day_of_week').eq(todayDayOfWeek)
    )
    
    for i in query_response['Items']:
            json_string = json.dumps(i)
            json_data = json.loads(json_string)
            
            streamTime = json_data['time_of_day']
            streamTimeSplit = streamTime.split(':')
            streamHour = int(streamTimeSplit[0])
            streamMin = int(streamTimeSplit[1])

            streamStartTime = streamStartTime.replace(hour=streamHour, minute=streamMin)
            cut_off_time = (streamStartTime + timedelta(hours=1))
            
            print("found a streaming time for today! " + str(streamStartTime) + " with cutoff " + str(cut_off_time))

            if (currentTimePacific >= streamStartTime) and (currentTimePacific < cut_off_time):
                print("Woo Hoo Active Stream Time!!")
                return True
        
    return False
