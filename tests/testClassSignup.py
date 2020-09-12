import boto3
import datetime
import json
import pytest
import pytz
import requests

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from pytz import timezone

def main():
	global authCookie
	global password
	global usertoken
	global today_class_date
	global today_class_time


	with open("credentials.json") as json_file:
            credentials = json.load(json_file)
            for pwd in credentials:
            	password = credentials['password']

	authCookie = signIn("testtest1", password)
	setupClasses()
	setupSignup()
	
	testCredits()
	testCancelPaidReservation()
	testCancelFreeReservation()
	test3HourCancelCutoff()
	testPaidCancelledClass()
	#testClassSpotsTaken

	#cleanupSignup()
	cleanupClasses()


def testCredits():
	print("in testCredits")
	#User testtest1 started with 7 credits and should have gone down to 5 (2 paid classes, 1 free)
	url = "https://6e32hgucc3.execute-api.us-east-2.amazonaws.com/sandbox/any"
	username = "testtest1"

	usertoken = signIn(username, password)
	headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}

	r= requests.post(url, headers=headers)
	response_dict = r.text
	json_data = json.loads(response_dict)

	paidLiveCredits = json_data['paidLiveCredits']
	try:
		assert(paidLiveCredits == "5")
	except AssertionError as e:
		print(str(e))
	

def testCancelPaidReservation():
	print("in testCancelPaidReservation")
	#CancelReservation URL
	cancelUrl = "https://do4iamsbnb.execute-api.us-east-2.amazonaws.com/sandbox/any"
	username = "testtest1"
	usertoken = signIn(username, password)
	headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}

	data = {
				"class_date": "2021-09-06"
		   }

	r= requests.post(cancelUrl, json.dumps(data), headers=headers)

	#Check that credit was refunded to reserved person
	getUserUrl = "https://6e32hgucc3.execute-api.us-east-2.amazonaws.com/sandbox/any"
	r= requests.post(getUserUrl, headers=headers)
	response_dict = r.text
	json_data = json.loads(response_dict)

	paidLiveCredits = json_data['paidLiveCredits']

	try:
		assert(paidLiveCredits == "6")
	except AssertionError as e:
		print(str(e))

	#Check that credit was charged to person moved off the waitlist
	username = "testtest2"
	usertoken = signIn(username, password)
	headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}
	r= requests.post(getUserUrl, headers=headers)
	response_dict = r.text
	json_data = json.loads(response_dict)
	paidLiveCredits = json_data['paidLiveCredits']
	try:
		assert(paidLiveCredits == "9")
	except AssertionError as e:
		print(str(e))

def testPaidCancelledClass():
	print('in testPaidCancelledClass')
	url = "https://hgggmyp4je.execute-api.us-east-2.amazonaws.com/sandbox/any"
	headers = {'Content-Type': 'application/json', 'x-api-key' : authCookie}

	utcmoment_naive = datetime.utcnow()
	utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
	currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
	today_class_date = currentTimePacific.strftime("%Y-%m-%d")

	data = {
				"class_date": today_class_date
		   }
	r= requests.post(url, json.dumps(data), headers=headers)


	#Check that credit was refunded to reserved person
	getUserUrl = "https://6e32hgucc3.execute-api.us-east-2.amazonaws.com/sandbox/any"
	username = "testtest4"
	usertoken = signIn(username, password)
	headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}

	r= requests.post(getUserUrl, headers=headers)
	response_dict = r.text
	json_data = json.loads(response_dict)

	paidLiveCredits = json_data['paidLiveCredits']

	try:
		assert(paidLiveCredits == "10")
	except AssertionError as e:
		print(str(e))

	#Check that class does not show up in upcoming classes
	#TODO - this won't work with my test data since it only gets classes for the current year
	getUpcomingClassesUrl = "https://0rzktwd2ae.execute-api.us-east-2.amazonaws.com/sandbox/any"
	r= requests.post(getUpcomingClassesUrl, headers=headers)
	print("response from getUpcomingClasses: " +r.text)
	response_dict = r.text
	json_data = json.loads(response_dict)
	classFound = False

	for i in json_data:
		if(i['class_date'] == today_class_date):
			classFound = True

	try:
		assert(classFound == False)
	except AssertionError as e:
		print(str(e))

	#TODO Need to test waitlisted person and make sure credits unchanged


def testCancelFreeReservation():
	print('in testCancelFreeReservation')
	cancelUrl = "https://do4iamsbnb.execute-api.us-east-2.amazonaws.com/sandbox/any"
	username = "testtest1"
	usertoken = signIn(username, password)
	headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}

	data = {
				"class_date": "2021-09-07"
		   }
	r= requests.post(cancelUrl, json.dumps(data), headers=headers)

	#Credits should be unaffected by canceling free class
	getUserUrl = "https://6e32hgucc3.execute-api.us-east-2.amazonaws.com/sandbox/any"
	r= requests.post(getUserUrl, headers=headers)
	response_dict = r.text
	json_data = json.loads(response_dict)

	paidLiveCredits = json_data['paidLiveCredits']
	try:
		assert(paidLiveCredits == "6")
	except AssertionError as e:
		print(str(e))


	#Credits should be unaffected by canceling free class - even for person moving off waitlist
	username = "testtest2"
	usertoken = signIn(username, password)
	headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}
	r= requests.post(getUserUrl, headers=headers)
	response_dict = r.text
	json_data = json.loads(response_dict)
	paidLiveCredits = json_data['paidLiveCredits']
	try:
		assert(paidLiveCredits == "9")
	except AssertionError as e:
		print(str(e))
	
#No easy way to clean this sucker up until I extend cancel class function
def test3HourCancelCutoff():
	print("in test3HourCancelCutoff")

	utcmoment_naive = datetime.utcnow()
	utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
	currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
	
	today_class_date = currentTimePacific.strftime("%Y-%m-%d")


	#signup for today's class
	url = "https://uz4pjq5u60.execute-api.us-east-2.amazonaws.com/sandbox/any"
	username = "testtest4"
	usertoken = signIn(username, password)
	headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}

	data = {
				"class_date": today_class_date
		   }
	r= requests.post(url, json.dumps(data), headers=headers)


	#Try to cancel reservation w/in 3 hour window - should get a 422 error
	cancelUrl = "https://do4iamsbnb.execute-api.us-east-2.amazonaws.com/sandbox/any"
	r= requests.post(cancelUrl, json.dumps(data), headers=headers)
	try:
		assert(r.status_code == 422)
	except AssertionError as e:
		print(str(e))
	

def setupSignup():
	print("in setupSignup")
	url = "https://uz4pjq5u60.execute-api.us-east-2.amazonaws.com/sandbox/any"
	i = 1

	while i < 10:
		username = "testtest" + str(i)

		usertoken = signIn(username, password)
		headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}

		with open("HighClasses.json") as json_file:
			classes = json.load(json_file)
			for high_class in classes:
	            	
					class_date = high_class['class_date']
					class_year_split = class_date.split('-')
					class_year = class_year_split[0]

					data = {
						"class_date": class_date
					}

					r= requests.post(url, json.dumps(data), headers=headers)
					
		i = i + 1


def cleanupSignup():
	print("in cleanupSignup")
	url = "https://do4iamsbnb.execute-api.us-east-2.amazonaws.com/sandbox/any"
	i = 1

	while i < 10:
		username = "testtest" + str(i)
		usertoken = signIn(username, password)
		headers = {'Content-Type': 'application/json', 'x-api-key' : usertoken}

		with open("HighClasses.json") as json_file:
			classes = json.load(json_file)
			for high_class in classes:
	            	
					class_date = high_class['class_date']
					class_year_split = class_date.split('-')
					class_year = class_year_split[0]

					data = {
						"class_date": class_date
					}

					r= requests.post(url, json.dumps(data), headers=headers)
					
		i = i + 1




def setupClasses():
	print("in setupClasses")
	#URL to Create Live Class Lambda
	url = "https://6o20zzkgdk.execute-api.us-east-2.amazonaws.com/sandbox/any"
	headers = {'Content-Type': 'application/json', 'x-api-key' : authCookie}
	global today_class_date
	global today_class_time

	with open("HighClasses.json") as json_file:
            classes = json.load(json_file)
            
            for high_class in classes:
            	data = {
            		"class_date": high_class['class_date'],
            		"class_time": high_class['class_time'],
            		"location" :  high_class['location'],
            		"spots_taken": high_class['spots_taken'],
            		"isFree": high_class['isFree']
        		}
            	r= requests.post(url, json.dumps(data), headers=headers)
    
    #add Class 2 hours from now to test 3 hour cancelation cutoff	
	utcmoment_naive = datetime.utcnow()
	utcmoment = utcmoment_naive.replace(tzinfo=pytz.utc)
	currentTimePacific = utcmoment.astimezone(timezone('US/Pacific'))
	cut_off_time = (currentTimePacific + timedelta(hours=2))
	today_class_date = cut_off_time.strftime("%Y-%m-%d")
	today_class_time = cut_off_time.strftime("%H:%M")

	data = {
    		"class_date": today_class_date,
    		"class_time": today_class_time,
    		"location" :  'phms',
    		"spots_taken": '0',
    		"isFree": 'False'
			}
	r= requests.post(url, json.dumps(data), headers=headers)

def signIn(username, password):
	#URL to Login Lambda
	url = "https://aeg5fvzujl.execute-api.us-east-2.amazonaws.com/sandbox/any"
	headers = {'Content-Type': 'application/json'}
	data = {"username": username, "password": password}

	r= requests.post(url, json.dumps(data), headers=headers)
	token = r.text
	return token


def cleanupClasses():
	print("in cleanupClasses")
	url = "https://hgggmyp4je.execute-api.us-east-2.amazonaws.com/sandbox/any"
	headers = {'Content-Type': 'application/json', 'x-api-key' : authCookie}

	with open("HighClasses.json") as json_file:
			classes = json.load(json_file)
            
			for high_class in classes:
            	
				class_date = high_class['class_date']
				class_year_split = class_date.split('-')
				class_year = class_year_split[0]

				data = {
					"class_date": class_date,
					"class_year": class_year
				}

				r= requests.post(url, json.dumps(data), headers=headers)
				#print("response from delete class: " + r.text)


if __name__ == '__main__':
    main()