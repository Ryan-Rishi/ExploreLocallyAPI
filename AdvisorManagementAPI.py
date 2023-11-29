import json
import boto3
import traceback
from flask import Flask, request, Response, jsonify
from flask_cors import CORS, cross_origin
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

app = Flask(__name__)
CORS(app)

cognito_client = boto3.client('cognito-idp')
user_pool_id = 'us-east-1_nhPJOw9sr'

dynamodb = boto3.resource('dynamodb')
advisor_table = dynamodb.Table('Advisor-Table')
advisor_application_table = dynamodb.Table('Advisor-Application-Table')


#http://127.0.0.1:5000/
@app.route('/')
@cross_origin()
def hello():
    return "Health Check!"


#http://127.0.0.1:5000/advisors_application/getall
@app.route('/advisors_application/getall', methods = ['GET'])
@cross_origin()
def get_advisors():
    try:
        response = advisor_application_table.scan(AttributesToGet=['username', 'phone_number', 'address', 'languages', 'interests', 'location'], Limit = 10)
        items = response.get('Items', [])
        usernames = [item['username'] for item in items]
        print(usernames)
        return jsonify(items)
    except Exception as e:
        return Response(response=json.dumps({"error": str(e)}), content_type='application/json', status=500)

#http://127.0.0.1:5000/advisors_application/approve/<username>
@app.route('/advisors_application/approve/<username>', methods = ['GET'])
@cross_origin()
def approve_advisor(username):
    try:
        dynamo_response = advisor_application_table.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('username').eq(username))
        items = dynamo_response.get('Items', [])
        item = items[0]

        new_item = {
            'username': username,
            'languages': item['languages'],
            'interests': item['interests'],
            'location': item['location'],
            'rating': 0,
            'rating_num': 0
        }

        advisor_table.put_item(Item = new_item)
        response = advisor_application_table.delete_item(Key={'username': username})
        return "Advisor Approved", 200
    except Exception as e:
        return Response(response=json.dumps({"error": str(e)}), content_type='application/json', status=500)
    

#http://127.0.0.1:5000/advisors_application/deny/<username>
@app.route('/advisors_application/deny/<username>', methods = ['POST'])
@cross_origin()
def deny_username(username):
    try:
        response = advisor_application_table.delete_item(Key={'username': username})
        return "Advisor Denied", 200
    except Exception as e:
        return Response(response=json.dumps({"error": str(e)}), content_type='application/json', status=500)
    
@app.route('/advisors_application/verify/<username>/<password>', methods = ['GET'])
@cross_origin()
def admin_login(username, password):
    if not username or not password:
        return "Username and password are required", 401
    
    try:
        response = cognito_client.initiate_auth(
            ClientId= '6i3masfta5g1u0g499720549rf',
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            }
        )

        return "User exists and password is correct", 200
    except cognito_client.exceptions.UserNotFoundException as e:
        return "User not found", 404
    except cognito_client.exceptions.NotAuthorizedException as e:
        return "Password is Incorrect", 402
    except ClientError as e:
        traceback.print_exc()
        return "Method Not Allowed", 405




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
