from flask import Flask, request, jsonify
from flask import Response
from flask_pymongo import PyMongo
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import ReturnDocument
from bson import json_util
import bcrypt
import jwt
import os
from datetime import datetime, timedelta
from bson.objectid import ObjectId

load_dotenv()
app = Flask(__name__)
CORS(app)
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
mongo = PyMongo(app)
secret_key = os.environ.get('SECRET_KEY')

def generate_token(user, secret_key, hours_to_expire=1):
    expiration_time = datetime.utcnow() + timedelta(hours=hours_to_expire)

    payload = {
        'id': str(user['_id']),
        'username': user['username'],
        'email': user['email'],
        'profession': user['profession'],
        'license': user['license'],
        'diaryblogAccess': user.get('diaryblogAccess'),
        'typeitAccess': user.get('typeitAccess'),
        'exp': expiration_time  # Use 'exp' claim for expiration
    }

    import jwt
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

def is_token_expired(token, secret_key):
    try:
        decoded_payload = jwt.decode(
            token, secret_key, algorithms=['HS256'])
        expiration_time = datetime.fromtimestamp(decoded_payload['exp'])
        current_time = datetime.utcnow()
        return current_time > expiration_time
    except jwt.ExpiredSignatureError:
        return True
    except jwt.InvalidTokenError:
        return True

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    profession = data.get('profession')
    license = data.get('license')
    diaryblog_access = data.get('diaryblogAccess')
    typeit_access = data.get('typeitAccess')
    createDate= datetime.utcnow()
    updateDate= datetime.utcnow()

    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user = mongo.db.users.insert_one({
        'email': email,
        'username': username,
        'password': hashed_password,
        'profession': profession,
        'license': license,
        'diaryblogAccess': diaryblog_access,
        'typeitAccess': typeit_access,
        'createDate': createDate,
        'updateDate': updateDate
    })

    user_id = user.inserted_id

    user_data = mongo.db.users.find_one({'_id': user_id})

    secret_key = os.environ.get('SECRET_KEY')

    token = generate_token(user_data, secret_key)

    data = json_util.dumps({'message': 'User registered successfully', 'user_id': str(user_id), 'token': token, 'user': user_data})
    return Response(data, mimetype='application/json'), 201

@app.route('/api/users/me', methods=['GET'])
def get_current_user_details():
    token = request.headers.get('Authorization')

    # Decode the token
    try:
        decoded_payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        user_id = decoded_payload['id']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({'message': 'Invalid or expired token'}), 401

    # Fetch user details from the database
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Extract user details (exclude sensitive information like password)
    user_data = {
        'email': user['email'],
        'username': user['username'],
        'profession': user.get('profession', None),
        'license': user.get('license', None),
        'diaryblogAccess': user.get('diaryblogAccess', None),
        'typeitAccess': user.get('typeitAccess', None),
        'createDate': user['createDate'],
        'updateDate': user['updateDate']
    }

    return jsonify(user_data), 200


@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = generate_token(user, secret_key)
    data = json_util.dumps({'message': 'Login successful', 'token': token, 'user': user})
    return Response(data, mimetype='application/json'), 200

@app.route('/api/menuOption', methods=['POST'])
def menuOption():
    secret_key = os.environ.get('SECRET_KEY')  # Use the secret key from environment variables
    token = request.headers.get('Authorization')  # Extract token from header
    token_expired = is_token_expired(token, secret_key)
    return jsonify({'message': 'Token verification successful', 'token_expired': token_expired}), 200

if __name__ == '__main__':
    app.run(debug=True)
