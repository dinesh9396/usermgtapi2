from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from pymongo import ReturnDocument
import bcrypt
import jwt
import datetime

app = Flask(__name__)
# Replace with your MongoDB URI
app.config['MONGO_URI'] = "mongodb+srv://mldinesh0:DPGq3M5xFkYGKfD6@cluster0.mnugi39.mongodb.net/indian_hacker_news?retryWrites=true&w=majority&tlsAllowInvalidCertificates=true"
mongo = PyMongo(app)


def generate_token(user, secret_key, hours_to_expire=1):
    # Calculate the expiration time
    expiration_time = datetime.datetime.utcnow(
    ) + datetime.timedelta(hours=hours_to_expire)

    payload = {
        'id': str(user['_id']),
        'name': user['name'],
        'email': user['email'],
        'profession': user['profession'],
        'license': user['license'],
        'diaryblogAccess': user.get('diaryblogAccess'),
        'typeitAccess': user.get('typeitAccess'),
        'expiration_time':  expiration_time
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

    user_id = mongo.db.users.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password,
        'profession': profession,
        'license': license,
        'diaryblogAccess': diaryblog_access,
        'typeitAccess': typeit_access,
    }).inserted_id

    return jsonify({'message': 'User registered successfully', 'user_id': str(user_id)}), 201


@app.route('/api/menuOption', methods=['POST'])
def menuOption():
    # add logic to fetch token from header and extract the data needed to be added
    secret_key = 'YourSecretKeyHere'
    token = is_token_expired(token, secret_key)
    return jsonify({'message': 'Login successful', 'token': token}), 200


if __name__ == '__main__':
    app.run(debug=True)
