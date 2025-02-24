import jwt
from datetime import datetime, timedelta, UTC

# Generate a JWT token
secret_key = "default-secret"  # Must match the jwt_secret in config.yml
algorithm = "HS256"
payload = {
    "roles": ["admin"],  # Must match allowed_roles in config.yml
    "exp": datetime.now(UTC) + timedelta(minutes=60),  # Token expiration time, 60 minutes from now
    "iat": datetime.now(UTC),  # Token issuance time
    "sub": "test-user"  # Subject of the token (optional)
}
valid_token = jwt.encode(payload, secret_key, algorithm=algorithm)
print(valid_token)