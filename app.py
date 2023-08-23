from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import ReturnDocument
from bson import json_util
from flask import Response
import bcrypt
import jwt
import datetime
import os

load_dotenv()
app = Flask(__name__)
CORS(app)
# Replace with your MongoDB URI
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
mongo = PyMongo(app)
secret_key = os.environ.get('SECRET_KEY')


def generate_token(user, secret_key, hours_to_expire=1):
    # Calculate the expiration time
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=hours_to_expire)

    payload = {
        'id': str(user['_id']),
        'name': user['name'],
        'email': user['email'],
        'profession': user['profession'],
        'license': user['license'],
        'diaryblogAccess': user.get('diaryblogAccess'),
        'typeitAccess': user.get('typeitAccess'),
        'exp': expiration_time  # Use 'exp' claim for expiration
    }

    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token



def is_token_expired(token, secret_key):
    try:
        decoded_payload = jwt.decode(
            token, secret_key, algorithms=['HS256'])
        expiration_time = datetime.datetime.fromtimestamp(
            decoded_payload['exp'])
        current_time = datetime.datetime.utcnow()
        return current_time > expiration_time
    except jwt.ExpiredSignatureError:
        return True
    except jwt.InvalidTokenError:
        return True


@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    profession = data.get('profession')
    license = data.get('license')
    diaryblog_access = data.get('diaryblogAccess')
    typeit_access = data.get('typeitAccess')

    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user = mongo.db.users.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password,
        'profession': profession,
        'license': license,
        'diaryblogAccess': diaryblog_access,
        'typeitAccess': typeit_access,
    })

    user_id = user.inserted_id

    user_data = mongo.db.users.find_one({'_id': user_id})

    secret_key = os.environ.get('SECRET_KEY')

    token = generate_token(user_data, secret_key)

    data = json_util.dumps({'message': 'User registered successfully', 'user_id': str(user_id), 'token': token, 'user': user_data})
    return Response(data, mimetype='application/json'), 201

@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Define your actual secret key here
    secret_key = os.environ.get('SECRET_KEY')

    token = generate_token(user, secret_key)
    data = json_util.dumps({'message': 'Login successful', 'token': token, 'user': user})
    return Response(data, mimetype='application/json'), 200




@app.route('/api/menuOption', methods=['POST'])
def menuOption():
    # Add logic to fetch token from header and extract the data needed to be added
    secret_key = 'YourSecretKeyHere'
    token = request.headers.get('Authorization')  # Extract token from header
    token_expired = is_token_expired(token, secret_key)
    return jsonify({'message': 'Token verification successful', 'token_expired': token_expired}), 200

if __name__ == '__main__':
    app.run(debug=True)
