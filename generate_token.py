import jwt
import os
from datetime import datetime, timedelta, UTC

# Generate a JWT token
secret_key = os.getenv('JWT_SECRET', 'default-secret')  # Use environment variable or fall back to default
algorithm = "HS256"

payload = {
    "roles": ["admin"],  # Must match allowed_roles in config.yaml
    "exp": datetime.now(UTC) + timedelta(minutes=60),  # Token expiration time, 60 minutes from now
    "iat": datetime.now(UTC),  # Token issuance time
    "sub": "test-user"  # Subject of the token (optional)
}

valid_token = jwt.encode(payload, secret_key, algorithm=algorithm)
print(valid_token)
