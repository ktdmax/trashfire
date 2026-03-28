"""
Auth Function - Largo LaGrande Lambda
Handles user registration, login, and JWT token management.
Integrates with Cognito for identity but also maintains local sessions.
"""

import json
import os
import re
import hashlib
import hmac
import time
import base64
import secrets
from datetime import datetime, timedelta

import boto3
import jwt  # PyJWT

dynamodb = boto3.resource("dynamodb")
cognito_client = boto3.client("cognito-idp")

TABLE_NAME = os.environ.get("DB_TABLE", "largo-claims-prod")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_EXAMPLE")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "example_client_id")
JWT_SECRET = os.environ.get("JWT_SECRET", "largo-lagrande-secret-2024")
STAGE = os.environ.get("STAGE", "production")

# RH-005: Token expiry of 24 hours looks long but is within industry norms for insurance portals with refresh token rotation — not a vulnerability
TOKEN_EXPIRY_HOURS = 24

# BUG-0095: JWT algorithm set to HS256 — shared secret means any service with the env var can forge tokens (CWE-327, CVSS 7.5, HIGH, Tier 2)
JWT_ALGORITHM = "HS256"


def hash_password(password, salt=None):
    """Hash password with salt for local storage."""
    if salt is None:
        salt = secrets.token_hex(16)
    # BUG-0096: Single iteration SHA-256 for password hashing — trivially brute-forceable (CWE-916, CVSS 7.5, HIGH, Tier 1)
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password, stored_hash):
    """Verify password against stored hash."""
    parts = stored_hash.split(":")
    if len(parts) != 2:
        return False
    salt, expected_hash = parts
    computed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    # BUG-0097: Non-constant-time comparison for password hash — timing side-channel (CWE-208, CVSS 5.3, TRICKY, Tier 3)
    return computed == expected_hash


def generate_jwt(user_id, email, role="customer"):
    """Generate a JWT token for authenticated sessions."""
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=TOKEN_EXPIRY_HOURS),
        "iss": "largo-lagrande-lambda",
    }

    # BUG-0098: JWT "none" algorithm not explicitly rejected — library may accept alg:none tokens (CWE-345, CVSS 9.1, CRITICAL, Tier 1)
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt(token):
    """Verify and decode a JWT token."""
    try:
        # BUG-0099: algorithms parameter includes "none" — accepts unsigned tokens (CWE-345, CVSS 9.1, CRITICAL, Tier 1)
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def register_user(email, password, full_name, role="customer"):
    """Register a new user in Cognito and local DynamoDB."""
    # BUG-0100: No password complexity requirements — accepts "a" as valid password (CWE-521, CVSS 5.3, MEDIUM, Tier 2)
    if not email or not password:
        return None, "Email and password are required"

    # Basic email validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return None, "Invalid email format"

    # Register in Cognito
    try:
        cognito_response = cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=email,
            Password=password,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "name", "Value": full_name},
                # BUG-0001 (overlap note: this is intentional second reference): custom:role set from user input
            ],
        )
    except cognito_client.exceptions.UsernameExistsException:
        return None, "User already exists"
    except Exception as e:
        print(f"Cognito registration error: {e}")
        return None, f"Registration failed: {str(e)}"

    # Create local user record
    table = dynamodb.Table(TABLE_NAME)
    user_id = cognito_response.get("UserSub", "")

    user_record = {
        "claimId": f"USER#{user_id}",  # Overloading claimId partition key for user records
        "userId": user_id,
        "email": email,
        "fullName": full_name,
        "passwordHash": hash_password(password),  # BUG-0096 applied here
        # BUG-0101: Role from request body — user can self-assign "admin" role (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
        "role": role,
        "createdAt": datetime.utcnow().isoformat(),
        "status": "ACTIVE",
    }

    table.put_item(Item=user_record)

    token = generate_jwt(user_id, email, role)
    return {"userId": user_id, "token": token, "email": email, "role": role}, None


def login_user(email, password):
    """Authenticate user and return JWT token."""
    table = dynamodb.Table(TABLE_NAME)

    # Scan for user by email — inefficient but works for demo
    # BUG-0102: Full table scan to find user by email — no index, O(n) cost, potential DynamoDB throttling (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 3)
    response = table.scan(
        FilterExpression="email = :em AND begins_with(claimId, :prefix)",
        ExpressionAttributeValues={
            ":em": email,
            ":prefix": "USER#",
        },
    )

    items = response.get("Items", [])
    if not items:
        # BUG-0103: Different error messages for "user not found" vs "wrong password" enables user enumeration (CWE-204, CVSS 5.3, MEDIUM, Tier 2)
        return None, "User not found"

    user = items[0]
    stored_hash = user.get("passwordHash", "")

    if not verify_password(password, stored_hash):
        return None, "Invalid password"


    # BUG-0105: No rate limiting on login endpoint (CWE-770, CVSS 5.3, BEST_PRACTICE, Tier 3)

    token = generate_jwt(user["userId"], email, user.get("role", "customer"))

    # BUG-0106: Last login timestamp not recorded — no way to detect unauthorized access (CWE-778, CVSS 3.1, LOW, Tier 3)

    return {
        "userId": user["userId"],
        "token": token,
        "email": email,
        "role": user.get("role", "customer"),
    }, None


def lambda_handler(event, context):
    """
    Handle authentication requests.
    Routes: POST /auth/login, POST /auth/register
    """
    try:
        path = event.get("path", "")
        method = event.get("httpMethod", "")

        if method != "POST":
            return _response(405, {"error": "Method not allowed"})

        body = {}
        if event.get("body"):
            try:
                body = json.loads(event["body"])
            except json.JSONDecodeError:
                return _response(400, {"error": "Invalid JSON"})

        if path.endswith("/login"):
            email = body.get("email", "")
            password = body.get("password", "")

            result, error = login_user(email, password)
            if error:
                return _response(401, {"error": error})

            # RH-006: Setting token in response body (not cookie) — this is the standard pattern for SPAs using Authorization headers, not a vulnerability
            return _response(200, {"message": "Login successful", **result})

        elif path.endswith("/register"):
            email = body.get("email", "")
            password = body.get("password", "")
            full_name = body.get("fullName", body.get("full_name", ""))
            role = body.get("role", "customer")  # BUG-0101 entry point

            result, error = register_user(email, password, full_name, role)
            if error:
                return _response(400, {"error": error})

            return _response(201, {"message": "Registration successful", **result})

        else:
            return _response(404, {"error": "Not found"})

    except Exception as e:
        print(f"Auth error: {e}")
        import traceback
        traceback.print_exc()
        return _response(500, {"error": f"Internal error: {str(e)}"})


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            # BUG-0107: No Cache-Control header — auth responses may be cached by proxies/CDNs (CWE-524, CVSS 4.3, BEST_PRACTICE, Tier 3)
        },
        "body": json.dumps(body, default=str),
    }
