import boto3
import json
import logging
from boto3.dynamodb.conditions import Key
from datetime import datetime
from botocore.exceptions import ClientError


logger = logging.getLogger('getPaidCredits-reconcile')
hdlr = logging.FileHandler('/var/log/credit-reconcile.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)

def main():
	global dynamodb
	global table 
	global oneFreeCreditUsers
	logger.info("----------------------------------------------------------------------------")
	
	dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
	table = dynamodb.Table('SiteUsers')
	scan_response = table.scan()
	oneFreeCreditUsers = ['redtabgirl', 'anita sagastegui', 'domzermeno', 'stefaniecody', 'karen888',  'dianabrownstein', 'sarahruby', 'kathynerin', 'glowing54', 'angelaguidi', 'anniesue03']

	for i in scan_response['Items']:
		json_string = json.dumps(i)
		json_data = json.loads(json_string)
		
		dbUser = json_data['username']

		paidClassesTaken = getPaidClassCountForUser(dbUser)
		totalCreditsPurchased = getTotalPaidCreditsForUser(dbUser)
		databaseCredits = getPaidCredits(dbUser)
		promoCredits = getPromoCreditCountForUser(dbUser)

		if(totalCreditsPurchased > 0):

			creditsRemaining = (totalCreditsPurchased + promoCredits) - paidClassesTaken
			if(creditsRemaining != databaseCredits and dbUser != 'dianatest'):
				sendEmail(dbUser)
				logger.info(dbUser + ": classes taken " + str(paidClassesTaken) + " totalCreditsPurchased " + str(totalCreditsPurchased) + 
					" Credits in system " + str(databaseCredits) + " calculatedCredits " + str(creditsRemaining ))


def getPromoCreditCountForUser(username):
	table = dynamodb.Table('HighPromoCredit')
	credits = 0
	
	query_response = table.query(
		KeyConditionExpression=Key('username').eq(username)
	)
	for i in query_response['Items']:
		promo_id = i['promo_id']
		credit_count = getPromoCreditCount(promo_id)
		credits = credits + credit_count

	logger.debug(str(credits) + " found in HighPromoCredit for " + username)
	return credits


def getPromoCreditCount(promo_id):
	table = dynamodb.Table('HighPromo')
	amount = 0
	credits = 0
	
	query_response = table.query(
		KeyConditionExpression=Key('promo_id').eq(promo_id)
	)
	for i in query_response['Items']:
		amount = int(i['amount'])
		credits = int(amount/10)

	return credits


def getTotalPaidCreditsForUser(username):
	table = dynamodb.Table('HighLivePayment')
	credits = 0

	#Adjust for people who helped me test
	if username in oneFreeCreditUsers:
		credits = credits + 1
	
	query_response = table.query(
		KeyConditionExpression=Key('username').eq(username)
	)
	for i in query_response['Items']:  
		amountPaid = i['amount-paid']
		if amountPaid == "10.00":
			credits = credits +1
		elif amountPaid == "35.00":
			credits = credits +4

	#if credits > 0:		
		#print(username + " has " + str(credits) + " credits")   

	logger.debug(str(credits) + " total paid credits found for " + username)   
	return credits


def getPaidClassCountForUser(username):
	table = dynamodb.Table('HighLiveClassSignup')
	query_response = table.query(
		KeyConditionExpression=Key('username').eq(username),
		IndexName="username-index"
	)
	countClasses = 0
	
	for i in query_response['Items']:
		class_date = i['class_date']
		reserve_position = i['reserve_position']

		#skip waitlists
		if(reserve_position == 0):
			continue

		class_year = datetime.now().strftime( "%Y")
		
		classtable = dynamodb.Table('HighClasses')
		classresponse = classtable.query(
		KeyConditionExpression=Key('class_year').eq(class_year) & Key('class_date').eq(class_date)
		)

		for l in classresponse['Items']:
			isFree = l['isFree']

			if isFree == "False":
				countClasses = countClasses + 1

	logger.debug(str(countClasses) + " class signups found for " + username)
	return countClasses

def getPaidCredits(username):
	
	table = dynamodb.Table('HighLiveCredits')
	credits = 0
	
	query_response = table.query(
		KeyConditionExpression=Key('username').eq(username)
	)
	for i in query_response['Items']:
		credits = i['credits']

	logger.debug(str(credits) + " found in HighLiveCredits for " + username)
	return credits

def sendEmail(username):
	
	SENDER = "anniecassiehigh@gmail.com"
	AWS_REGION = "us-east-2"
	SUBJECT = "Double Check User Credits"
	CHARSET = "UTF-8"

	BODY_TEXT = ("Double Check User Credits for " + username)
	BODY_HTML = """<html><head></head><body>
  <h1>Possible Class Credit Miscalculation</h1>
  <p>Double Check User Credits for """ + username + """</p> 
</body></html>
 """
	email = ["dlmca@yahoo.com", "spinbikehaxor@gmail.com", "anniecassiehigh@gmail.com"]
	client = boto3.client('ses',region_name=AWS_REGION)


	try:
	#Provide the contents of the email.
		logger.debug("sending email to " + str(email))
		response = client.send_email(
			Destination={
				'ToAddresses': 
					 email
				,
			},
			Message={
				'Body': {
					'Html': {
						'Charset': CHARSET,
						'Data': BODY_HTML,
						},
					'Text': {
						'Charset': CHARSET,
						'Data': BODY_TEXT,
					},
				},
				'Subject': {
					'Charset': CHARSET,
					'Data': SUBJECT,
				},
			},
			Source=SENDER,
		# If you are not using a configuration set, comment or delete the
		# following line
		#ConfigurationSetName=CONFIGURATION_SET,
	)
# Display an error if something goes wrong. 
	except ClientError as e:
		print(e.response['Error']['Message'])
	else:
		print("Email sent! Message ID:"),
		print(response['MessageId'])
	
	return {
		'statusCode': 200,
		'headers': {
			'Access-Control-Allow-Headers': '*',
			'Access-Control-Allow-Origin':  '*',
			'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
		},
		'body': json.dumps('Class Credit Email Sent!')
	}

if __name__ == '__main__':
	main()

