
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from pymongo import ReturnDocument
import bcrypt
import jwt

app = Flask(__name__)
app.config['MONGO_URI'] =  "mongodb+srv://mldinesh0:DPGq3M5xFkYGKfD6@cluster0.mnugi39.mongodb.net/indian_hacker_news?retryWrites=true&w=majority&tlsAllowInvalidCertificates=true"
  # Update the MongoDB URI as needed
mongo = PyMongo(app)

# Function to generate a JWT token for a user
def generate_token(user):
    # Define the JWT payload with user data
    payload = {
        'id': str(user['_id']),
        'name': user['name'],
        'email': user['email'],
        'profession': user['profession'],
        'license': user['license'],
    }

    # Sign the token with your secret key and set expiration time
    secret_key = 'Vinoth'  # Replace with your actual secret key
    expiration = 3600  # Token will expire after 1 hour (you can adjust this as needed)

    # Generate the JWT token
    token = jwt.encode(payload, secret_key, algorithm='HS256')

    return token

# User Registration API
@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    profession = data.get('profession')
    license = data.get('license')

    # Check if user with the same email already exists
    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    # Hash the password before storing in the database
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert user into the database
    user_id = mongo.db.users.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password,
        'profession': profession,
        'license': license
    }).inserted_id

    return jsonify({'message': 'User registered successfully', 'user_id': str(user_id)}), 201


# User Login API
@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})

    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    # Check if the provided password matches the hashed password in the database
    if bcrypt.checkpw(password.encode('utf-8'), user['password']):
        # Generate the JWT token for the authenticated user
        token = generate_token(user)
        return jsonify({'message': 'Login successful', 'token': token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

if __name__ == '__main__':
    app.run(debug=True)
