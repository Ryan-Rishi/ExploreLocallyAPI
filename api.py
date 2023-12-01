import json
import boto3
from flask import Flask, request, Response, jsonify
from flask_cors import CORS, cross_origin
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

app = Flask(__name__)
CORS(app)

cognito_client = boto3.client('cognito-idp')
user_pool_id = 'us-east-1_k1xovBg3P'

dynamodb = boto3.resource('dynamodb')
user_table = dynamodb.Table('User-Table')
advisor_table = dynamodb.Table('Advisor-Table')
advisor_application_table = dynamodb.Table('Advisor-Application-Table')


#http://127.0.0.1:5000/
@app.route('/')
@cross_origin()
def hello():
    return "Health Check!"

def email_exists(email):
    try:
        response = cognito_client.list_users(
            UserPoolId=user_pool_id,
            Filter=f'email = "{email}"',
        )
        return bool(response.get('Users'))
    except ClientError as e:
        print(f"An error occurred when checking the email: {e}")
        return False

#http://127.0.0.1:5000/users/register/<username>/<password>
@app.route('/users/register/<username>/<password>/<email>', methods = ['POST'])
@cross_origin()
def register_user(username, password, email):
    try:
        if not username or not password:
            return "Username, email, and password are required", 401

        if email_exists(email):
            return "Email already exists", 401

        cognito_client.sign_up(
            ClientId='73tr5iabe4sulif3qnqn0gthsu',
            Username=username,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
            ]
        )

        user_table.put_item(Item={'username': username})


        return "User registered successfully", 200
    except cognito_client.exceptions.UsernameExistsException as e:
        return "Username already exists", 401
    except cognito_client.exceptions.InvalidPasswordException as e:
        return "Password does not meet requirements", 401
    except ClientError as e:
        return Response(response=json.dumps({"error": str(e)}), content_type='application/json', status=400)


#http://127.0.0.1:5000/advisors/register/<username>/<password>
@app.route('/advisors/register/<username>/<password>/<email>/<number>/<address>', methods = ['POST'])
@cross_origin()
def register_advisor_account(username, password, email, number, address):
    try:
        if not username or not password:
            return "Username, email, and password are required", 401

        if email_exists(email):
            return "Email already exists", 401

        cognito_client.sign_up(
            ClientId='73tr5iabe4sulif3qnqn0gthsu',
            Username=username,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
            ]
        )

        item = {
            'username': username,
            'phone_number': number,
            'address': address
        }

        advisor_application_table.put_item(Item = item)

        return "User registered successfully", 200
    except cognito_client.exceptions.UsernameExistsException as e:
        return "Username already exists", 401
    except cognito_client.exceptions.InvalidPasswordException as e:
        return "Password does not meet requirements", 401
    except ClientError as e:
        return "Method Not Allowed", 405





#http://127.0.0.1:5000/advisors/registerinformation/<username>/<password>
@app.route('/advisors/registerinformation/<username>/<number>/<address>', methods = ['POST'])
@cross_origin()
def register_advisor_information(username, number, address):
        data = request.json

        languages_set = set(data.get('languages', []))
        interests_set = set(data.get('interests', []))
        location = data.get('location')

        item = {
            'username': username,
            'phone_number': number,
            'address': address,
            'languages': list(languages_set),
            'interests': list(interests_set),
            'location': location
        }

        advisor_application_table.put_item(Item = item)

        return "Advisor Updated", 200



#http://127.0.0.1:5000/users/verify/<username>/<password>
@app.route('/users/verify/<username>/<password>', methods = ['GET'])
@cross_origin()
def user_login(username, password):
    if not username or not password:
        return "Username and password are required", 401

    try:
        response = cognito_client.initiate_auth(
            ClientId= '73tr5iabe4sulif3qnqn0gthsu',
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            }
        )

        dynamo_response = user_table.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('username').eq(username))
        items = dynamo_response.get('Items', [])

        if len(items) > 0:
            return "User exists and password is correct", 200
        else:
            return "User not yet approved", 404
    except cognito_client.exceptions.UserNotFoundException as e:
        return "User not found", 404
    except cognito_client.exceptions.NotAuthorizedException as e:
        return "Password is Incorrect", 402
    except ClientError as e:
        return "Method Not Allowed", 405


#http://127.0.0.1:5000/advisor/verify/<username>/<password>
@app.route('/advisors/verify/<username>/<password>', methods = ['GET'])
@cross_origin()
def advisor_login(username, password):
    if not username or not password:
        return "Username and password are required", 401
    try:
        response = cognito_client.initiate_auth(
            ClientId= '73tr5iabe4sulif3qnqn0gthsu',
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            }
        )

        dynamo_response = advisor_table.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('username').eq(username))
        items = dynamo_response.get('Items', [])

        if len(items) > 0:
            return "User exists and password is correct", 200
        else:
            return "User not yet approved", 404
    except cognito_client.exceptions.UserNotFoundException as e:
        return "User not found", 404
    except cognito_client.exceptions.NotAuthorizedException as e:
        return "Password is Incorrect", 402
    except ClientError as e:
        return "Method Not Allowed", 405

#http://127.0.0.1:5000/advisors/query
@app.route('/advisors/query', methods=['GET'])
@cross_origin()
def query_advisors():

    languages = request.args.get('languages')
    location = request.args.get('location')
    interests = request.args.get('interests')

    try:
        # Initial query with all filters
        scan_args = {
            'FilterExpression': Attr('location').eq(location)
        }

        if languages:
            scan_args['FilterExpression'] = scan_args['FilterExpression'] & Attr('languages').contains(languages)

        if interests:
            for interest in interests.split(','):
                scan_args['FilterExpression'] = scan_args['FilterExpression'] & Attr('interests').contains(interest)

        response = advisor_table.scan(**scan_args)
        items = response.get('Items', [])

        # Check if response is empty and location is set
        if not items and location:
            print("Requerying without interests")
            scan_args.pop('FilterExpression', None)
            scan_args['FilterExpression'] = Attr('location').eq(location)

            if languages:
                scan_args['FilterExpression'] = scan_args['FilterExpression'] & Attr('languages').contains(languages)

            response = advisor_table.scan(**scan_args)
            items = response.get('Items', [])

        sorted_items = sorted(
        items,
        key=lambda x: (
            float(x.get('rating', 0)) / float(x['rating_num']) if x.get('rating_num', 1) != 0 else float(x.get('rating', 0))
            ),reverse=True
        )

        for item in sorted_items:
            for key, value in item.items():
                if isinstance(value, Decimal):
                    item[key] = str(value)
        return jsonify(sorted_items)

    except ClientError as e:
        print(f"An error occurred: {e}")
        return jsonify({"error": str(e)}), 500


#http://127.0.0.1:5000/advisors/rating/<username>
@app.route('/advisors/rating/<username>', methods=['GET'])
@cross_origin()
def get_advisor_rating(username):
    try:
        response = advisor_table.get_item(
            Key={'username': username},
            AttributesToGet=['rating', 'rating_num']
        )
        item = response.get('Item', None)

        if not item:
            return jsonify({
                'username': username,
                'average_rating': None,
                'message': 'No User Found'
            }), 404

        if item['rating_num'] == 0:
            return jsonify({
                'username': username,
                'average_rating': None,
                'message': 'No Rating'
            }), 200

        # Convert Decimal to float for JSON serialization
        average_rating = float(item['rating']) / int(item['rating_num'])

        return jsonify({
            'username': username,
            'average_rating': average_rating
        }), 200
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({
            'error': str(e)
        }), 500

# Route to update the rating of an advisor
# The <username> is a placeholder for the advisor's username
# The <rating> is a placeholder for the rating given by the user, expected to be a number from 1 to 5
#http://127.0.0.1:5000/advisors/rate/<username>/<int:rating>
@app.route('/advisors/rate/<username>/<int:rating>', methods=['POST'])
@cross_origin()
def rate_advisor(username, rating):
    if not username or rating not in range(1, 6):
        return jsonify({'message': 'Username and valid rating (1-5) are required'}), 400

    try:
        # Fetch the current rating data for the advisor
        response = advisor_table.get_item(Key={'username': username})
        item = response.get('Item', None)

        if not item:
            return jsonify({'message': 'Advisor not found'}), 404

        # Update the rating and rating number
        new_rating_num = int(item.get('rating_num', 0)) + 1
        new_rating_total = int(item.get('rating', 0)) + rating
        new_average_rating = new_rating_total / new_rating_num

        if new_average_rating < 3 and new_rating_num > 10:
            # Delete the advisor from the table if the average rating is less than 3
            advisor_table.delete_item(Key={'username': username})
            return jsonify({'message': 'Advisor deleted due to low rating'}), 200
        else:
            # Update the item in the DynamoDB table
            advisor_table.update_item(
                Key={'username': username},
                UpdateExpression='SET rating = :r, rating_num = :rn',
                ExpressionAttributeValues={
                    ':r': new_rating_total,
                    ':rn': new_rating_num
                }
            )
            return jsonify({'message': 'Rating updated successfully'}), 200
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': str(e)}), 500



#http://127.0.0.1:5000/advisors/getall
@app.route('/advisors/getall', methods = ['GET'])
@cross_origin()
def get_advisors():
    try:
        # Just get top 10 advisors
        response = advisor_table.scan(AttributesToGet=['username', 'location', 'interests', 'languages', 'rating', 'rating_num'], Limit = 10)
        items = response.get('Items', [])
        sorted_items = sorted(
            items,
            key=lambda x: (
                float(x.get('rating', 0)) / float(x['rating_num']) if x.get('rating_num', 1) != 0 else float(x.get('rating', 0))
            ),
            reverse=True  # For descending order
        )

        for item in sorted_items:
            # Then iterate over each key-value pair in the dictionary
            for key, value in item.items():
                # If the value is a Decimal, convert it to a string
                if isinstance(value, Decimal):
                    item[key] = str(value)

        #advisor_response = json.dumps(usernames)
        #return Response(response=advisor_response, content_type='application/json', status=200)
        return jsonify(sorted_items)
    except Exception as e:
        return Response(response=json.dumps({"error": str(e)}), content_type='application/json', status=500)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
