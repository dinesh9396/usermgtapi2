# User Management API

## License

This project is licensed under a private license. All rights reserved. Unauthorized use, reproduction, or distribution of this software is strictly prohibited. Contact the author for more information.

© 2023 Universe

## Description

This is a Flask-based API for user registration and login, utilizing MongoDB for data storage, bcrypt for password hashing, and JWT for token-based authentication. The API allows users to register, log in, and receive a JWT token for accessing protected routes.

## Features

- User Registration: Users can register by providing their name, email, password, profession, and license information.
- User Login: Registered users can log in with their email and password to receive a JWT token.
- JWT Authentication: JWT tokens are used to authenticate users for protected routes.
- MongoDB Integration: User data is stored in a MongoDB database using the Flask-PyMongo extension.
- Password Hashing: User passwords are securely hashed using bcrypt.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/HackerNewsIndia/UserMgtAPI.git
cd your-repo
```

2. Create and activate a virtual environment (optional but recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

4. Set environment variables:

   - `MONGO_URI`: Replace with your MongoDB URI.

5. Run the Flask application:

```bash
python app.py
```

The application will be running at `http://127.0.0.1:5000/`.

## API Endpoints

- `POST /api/register`: Register a new user. Requires the following JSON payload:

```json
{
  "name": "John Doe",
  "email": "john.doe@example.com",
  "password": "your_password",
  "profession": "Developer",
  "license": "MIT",
  "diaryblogAccess": true,
  "typeitAccess": false
}
```

- `POST /api/login`: Log in a user and receive a JWT token. Requires the following JSON payload:

```json
{
  "email": "john.doe@example.com",
  "password": "your_password"
}
```

```
Code to check is_token_expired need to add this logic
import jwt
import datetime

def is_token_expired(token):
    try:
        decoded_payload = jwt.decode(token, 'YourSecretKeyHere', algorithms=['HS256'])
        expiration_time = datetime.datetime.fromtimestamp(decoded_payload['exp'])
        current_time = datetime.datetime.utcnow()
        return current_time > expiration_time
    except jwt.ExpiredSignatureError:
        return True
    except jwt.InvalidTokenError:
        return True

# Example usage:
token = "your_jwt_token_here"
expired = is_token_expired(token)
if expired:
    print("Token has expired.")
else:
    print("Token is still valid.")

```

## Author

- Vinoth
- Dinesh
