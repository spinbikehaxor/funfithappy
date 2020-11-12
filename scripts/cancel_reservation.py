import boto3
import json
import logging
from boto3.dynamodb.conditions import Key
from datetime import datetime
from botocore.exceptions import ClientError

def main():
    global dynamodb
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    users = ['rachaelannt']

    for i in users:
        deleteAndCreditReservations(i, '2020-11-11')



def deleteAndCreditReservations(username, class_date):
    print("in deleteAndCreditReservations")
    
    table = dynamodb.Table('HighLiveClassSignup')
    
    query_response = table.query(
        KeyConditionExpression=Key('class_date').eq(class_date)
    )
    
    for i in query_response['Items']:
        dbName = i['username']

        if username != dbName:
            print("dbName = " + dbName + " username = " + username + " so continuing loop")
            continue

        spot_number = i['reserve_position']
        waitlist_number = i['waitlist_position']
        
        #Paid class is being cancelled, so credit users with reserved spots
        if not isClassFree(class_date) and (spot_number > 0 and waitlist_number == 0):
            print('returning paid credit for ' + username)
            returnPaidCredit(username)
        
        #Delete reservation
        print("deleting reservation")
        response = table.delete_item(
           Key={
                'username': username,
                'class_date': class_date
           }
        )
        reorderPositions(class_date, True, False, 24)
        decrementSpotsTaken(class_date)
            
def returnPaidCredit(username):
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

def isClassFree(class_date):
    print("in getClassDetails " + class_date)

    table = dynamodb.Table('HighClasses')
    location = ''
    classDateObj = datetime.strptime(class_date, '%Y-%m-%d')
    class_year = classDateObj.strftime( "%Y")
    isFree = False
    class_time = ''
  
    response = table.query(
        KeyConditionExpression=Key('class_year').eq(class_year) & Key('class_date').eq(class_date)
    )
    for i in response['Items']:
        location = i['location']
        class_time = i['class_time']
        if 'isFree' in i.keys():
            isFreeString = i['isFree']
            if isFreeString == "True":
                isFree = True
   
    return isFree

def decrementSpotsTaken(class_date):
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('HighClasses')
    
    classDateObj = datetime.strptime(class_date, '%Y-%m-%d')
    class_year = classDateObj.strftime( "%Y")
    
    try:
        response = table.update_item(
            Key={
                'class_date': class_date,
                'class_year': class_year
            },
            UpdateExpression='SET #spots_taken = if_not_exists(#spots_taken, :zero) - :incr',
            ConditionExpression="#spots_taken > :zero",
            ExpressionAttributeNames =  {
                    '#spots_taken': 'spots_taken'
                },
            ExpressionAttributeValues={
                ':incr': 1, ':zero': 0
            },
            ReturnValues="UPDATED_NEW"
        )
    except ClientError as e:
        if e.response['Error']['Code'] == "ConditionalCheckFailedException":
            print(e.response['Error']['Message'])
        else:
            raise
    else:
        return response


def reorderPositions(class_date, reserved, isFree, capacity):
    reservationList = []
    sorted_reservations = []
    
    #Pull all records for class date
    table = dynamodb.Table('HighLiveClassSignup')
    query_response = table.query(
        KeyConditionExpression=Key('class_date').eq(class_date)
    )
    
    #Create a sorted list based on signup time
    for reservation in query_response['Items']:
        data = {
            "username"      : reservation['username'],
            'signup_time'   : reservation['signup_time']
        }
        
        reservationList.append(data)
    sorted_reservations = sorted(reservationList, key = lambda i: i['signup_time'])
    
    print (len(sorted_reservations))
    
    #Loop through sorted list and update the roster numbers
    i = 0
    while(i < len(sorted_reservations)): 
        
        classCountIter = i + 1
        
        reservation = sorted_reservations[i]
        print(str(reservation))
        resSpot = 0
        waitSpot = 0
        
        reservation = sorted_reservations[i]
        
        #Update resSpot for people already in the class
        if classCountIter < capacity:
            resSpot = classCountIter
            
        #If a reservation was cancelled (vs a waitlist) bump the first person up from the waitlist and charge a credit    
        elif classCountIter == capacity and reserved:
            resSpot = classCountIter
            if not isFree:
                chargeCreditForBumpedUpUser(reservation['username'])
            
        #Reorder the waitlist
        elif classCountIter > capacity:
            waitSpot = classCountIter - capacity
    
        update_response = table.update_item(
            Key={
            'class_date': class_date,
            'username': reservation['username']
            },
           UpdateExpression="set reserve_position=:r, waitlist_position=:w",
            ExpressionAttributeValues={
                ':r': resSpot,
                ':w': waitSpot
            },
            ReturnValues="UPDATED_NEW"
        )
        i += 1


if __name__ == '__main__':
    main()