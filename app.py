from flask import Flask, request, jsonify, session
from flask_pymongo import PyMongo
from bson import ObjectId
import bcrypt
import os
from dotenv import load_dotenv
import jwt
import datetime  # Import the datetime module

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)

# Configure MongoDB connection
app.config['MONGO_URI'] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
users_collection = mongo.db.users

# Secret key for session management
app.secret_key = os.getenv("SECRET_KEY")

jwt_secret_key = os.getenv("JWT_SECRET_KEY")

if jwt_secret_key is None or not isinstance(jwt_secret_key, str):
    raise ValueError("JWT_SECRET_KEY is not set or is not a string")

# Endpoint for user registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json

    # Check if email is already registered
    existing_user = users_collection.find_one({"email": data["email"]})
    if existing_user:
        return jsonify({"message": "Email already registered"}), 400

    # Hash the password securely
    hashed_password = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt())

    # Create a new user document with corrected fields
    user_id = mongo.db.users.insert_one({
        "email": data["email"],
        "username": data["username"],
        "password": hashed_password,
        "createDate": datetime.datetime.utcnow(),
        "updateDate": datetime.datetime.utcnow(),
        "diaryblogAccess": data.get('diaryblogAccess'),  # Corrected line
        "typeitAccess": data.get('typeitAccess')  # Corrected line
    })

    return jsonify({"message": "Registration successful"}), 201

# Endpoint for user login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = users_collection.find_one({"email": data["email"]})

    if user:
        # Check the hashed password
        if bcrypt.checkpw(data["password"].encode('utf-8'), user["password"]):
            # Generate a JWT token upon successful login
            token_payload = {
                "user_id": str(user["_id"]),
                "email": user["email"],
                "username": user["username"]
            }
            token = jwt.encode(token_payload, jwt_secret_key, algorithm='HS256')

            # Return the JWT token as a response
            return jsonify({"message": "Login successful", "token": token}), 200
        else:
            return jsonify({"message": "Incorrect password"}), 401
    else:
        return jsonify({"message": "User not found"}), 404

# Endpoint for user logout (no changes)

if __name__ == '__main__':
    app.run(debug=True)
