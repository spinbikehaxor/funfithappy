import json
import binascii
import boto3
import base64
import hashlib
import html
import os
import phonenumbers
import re
import uuid

import django
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.conf import settings
from email_validator import validate_email, EmailNotValidError

def lambda_handler(event, context):
    print("In lambda_handler")

    #Initialize django's password validation library
    init_validator()
    json_string = json.dumps(event)
    print(json_string)
    json_data = json.loads(json_string)
    body = json.loads(json_data['body'])
    isValidPhone = False
    
    if 'username' not in body.keys():
        print("No creds received")
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("Username Is Required")
        }
    else:
        username = body['username']
        password = body['password']
        fname = body['fname']
        lname = body['lname']
        email = body['email']
        phone = body['phone']
        preferredContact = body['preferredContact']

    try:
        formattedPhone = phonenumbers.parse(phone, "US")
        isValidPhone = phonenumbers.is_valid_number(formattedPhone)
    except:
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("The phone number entered appears invalid")
        }
    if not isValidPhone:
        print("invalid phone")
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("The phone number entered appears invalid")
        }

    #Validate email
    try:
        valid = validate_email(email)
    except EmailNotValidError as e:
        # email is not valid, exception message is human-readable
        print(str(e))
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("The email entered appears invalid")
        }

    #Validate length, commonality of password and prohibit all numeric
    try:
        pwdValidation = password_validation.validate_password(password)
    except ValidationError as err:
        print("invalid password")
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps(dict(list(enumerate(err))))
        }

    #Check if user has already registered
    if is_dup(username, email, phone):
        print("dup account")
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("An account with this information already exists. Please click forgot password if needed.")
        }

    if not fname or not lname or not username:
        print("missing name values")
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("All fields are required. Please complete missing information")
        }
    if len(username) < 8:
        print('username too short')
        return {
            'statusCode': 422,
            'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps("Username must be at least 8 characters")
        }


        
    passHash = hash_password(password.strip());
        
    print("saving to DB")
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('SiteUsers')

    formatted_username = username.lower().strip()
    
    response = table.put_item(
        Item={
            'username': html.escape(formatted_username),
            'password': passHash,
            'fname': html.escape(fname.strip()),
            'lname' : html.escape(lname.strip()),
            'email': html.escape(email),
            'phone': html.escape(phone),
            'preferredContact': html.escape(preferredContact)
        }
    )
        
    print(response)
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps('Participant written to DynamoDB!')
    }

def is_dup(username, email, phone):
    print ("in check_for_dups")
    dynamodb = boto3.resource('dynamodb', region_name='us-east-2', endpoint_url="https://dynamodb.us-east-2.amazonaws.com")
    table = dynamodb.Table('SiteUsers')
    
    scan_response = table.scan();
    for i in scan_response['Items']:
        json_string = json.dumps(i)
        json_data = json.loads(json_string)
        
        dbuser = json_data['username']
        dbemail = json_data['email']
        dbphone = json_data['phone']
        print("checking values against db values for dups")
        if(dbuser == username or dbemail == email or dbphone == phone):
            return True


def init_validator():
    if not settings.configured:
        settings.configure(AUTH_PASSWORD_VALIDATORS = [
            {
                'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
                'OPTIONS': {
                    'min_length': 8,
                }
            },
            {
                'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
            },
            {
                'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
            },
        ]
        )
        django.setup()

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')
 