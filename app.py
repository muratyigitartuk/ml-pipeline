"""
Machine Learning Pipeline API
Copyright (c) 2025 Murat Yigit Artuk
License: MIT
"""

import logging
import os
import threading
from datetime import datetime, UTC
from functools import lru_cache, wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path
from time import sleep
from typing import Dict, List, Optional, Union

import joblib
import jwt
import numpy as np
import yaml
from flasgger import Swagger, swag_from
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_client import Counter, Histogram, Summary
from pydantic import BaseModel, ValidationError
from werkzeug.exceptions import HTTPException

# Debug mode configuration (disabled by default for production safety)
DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
if DEBUG:
    import warnings
    warnings.warn("Debug mode is active! Should be disabled in production.")

# Basic configuration settings
CONFIG_PATH = Path(os.getenv('CONFIG_PATH', 'config.yaml'))
MODEL_RETRIES = int(os.getenv('MODEL_RETRIES', '3'))
MODEL_RETRY_DELAY = int(os.getenv('MODEL_RETRY_DELAY', '5'))
MAX_REQUEST_SIZE = int(os.getenv('MAX_REQUEST_SIZE', '1048576'))  # 1MB
CACHE_SIZE = int(os.getenv('CACHE_SIZE', '1024'))

# Logging configuration
LOG_FILE = os.getenv('LOG_FILE', 'ml-api.log')
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
)
file_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=LOG_BACKUP_COUNT
)
file_handler.setFormatter(log_formatter)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    handlers=[file_handler, stream_handler]
)
logger = logging.getLogger('ml-api')

# Prometheus metrics for monitoring
METRICS = {
    'requests_total': Counter(
        'http_requests_total',
        'Total HTTP Requests',
        ['method', 'endpoint', 'status']
    ),
    'request_duration': Histogram(
        'http_request_duration_seconds',
        'HTTP request duration in seconds',
        ['endpoint']
    ),
    'prediction_duration': Summary(
        'prediction_duration_seconds',
        'Model prediction duration in seconds'
    ),
    'model_load_duration': Summary(
        'model_load_duration_seconds',
        'Model loading duration in seconds'
    ),
    'errors_total': Counter(
        'http_errors_total',
        'Total HTTP Errors',
        ['type']
    )
}

class SecurityConfig(BaseModel):
    """Security configuration class"""
    jwt_secret: str = os.getenv('JWT_SECRET', 'default-secret')  # Default secret for fallback
    jwt_algorithm: str = 'HS256'
    token_expire_minutes: int = 60

class ModelConfig(BaseModel):
    """Model configuration class"""
    model_path: str
    n_features: int
    input_validation: Dict[str, Union[float, int]] = {'min_value': -1e6, 'max_value': 1e6}

class AppConfig(BaseModel):
    """Main application configuration class"""
    model: ModelConfig
    security: SecurityConfig
    allowed_roles: List[str] = ['admin']
    rate_limit: str = '100/minute'
    nan_replacement: float = 0.0
    enable_auth: bool = True
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None

    @classmethod
    def validate_ssl_files(cls, v: Optional[str]) -> Optional[str]:
        """Validate SSL files existence"""
        if v and not Path(v).exists():
            raise ValueError(f"SSL file not found: {v}")
        return v

def load_config() -> AppConfig:
    """Load configuration securely from file and environment variables"""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Config file not found at: {CONFIG_PATH}")

    try:
        with open(CONFIG_PATH, 'r') as f:
            config_data = yaml.safe_load(f) or {}

        # Ensure 'model' section exists
        if 'model_path' in config_data and 'model' not in config_data:
            config_data['model'] = {
                'model_path': config_data.pop('model_path'),
                'n_features': config_data.pop('n_features', 10),
                'input_validation': config_data.pop('input_validation', {'min_value': -1e6, 'max_value': 1e6})
            }
        elif 'model' not in config_data:
            raise ValueError("Missing 'model' configuration section in config.yaml")

        # Ensure 'security' section exists with defaults
        if 'jwt_secret' in config_data and 'security' not in config_data:
            config_data['security'] = {
                'jwt_secret': config_data.pop('jwt_secret', os.getenv('JWT_SECRET', 'default-secret')),
                'jwt_algorithm': config_data.pop('jwt_algorithm', 'HS256'),
                'token_expire_minutes': config_data.pop('token_expiry', 60)
            }
        elif 'security' not in config_data:
            config_data['security'] = {
                'jwt_secret': os.getenv('JWT_SECRET', 'default-secret'),
                'jwt_algorithm': 'HS256',
                'token_expire_minutes': 60
            }

        # Override with environment variables
        env_mapping = {
            "model.model_path": "MODEL_PATH",
            "model.n_features": "N_FEATURES",
            "security.jwt_secret": "JWT_SECRET",
            "rate_limit": "RATE_LIMIT",
            "enable_auth": "ENABLE_AUTH",
            "ssl_cert": "SSL_CERT",
            "ssl_key": "SSL_KEY"
        }

        for config_path, env_var in env_mapping.items():
            env_value = os.getenv(env_var)
            if env_value:
                parts = config_path.split('.')
                target = config_data
                for part in parts[:-1]:
                    target = target.setdefault(part, {})
                target[parts[-1]] = env_value

        return AppConfig(**config_data)
    except Exception as error:
        logger.critical(f"Configuration error: {str(error)}. Please ensure 'model' and 'security' sections are correctly defined in config.yaml")
        raise

config = load_config()

# Custom exception classes
class MLAPIException(Exception):
    """Base exception class for API errors"""
    status_code = 500

class ModelLoadError(MLAPIException):
    """Exception for model loading failures"""
    status_code = 503

class ModelValidationError(MLAPIException):
    """Exception for model validation failures"""
    status_code = 422

class PredictionError(MLAPIException):
    """Exception for prediction failures"""
    status_code = 500

class ModelNotReadyError(MLAPIException):
    """Exception for when the model is not ready"""
    status_code = 503

class MLPipeline:
    """Thread-safe machine learning prediction pipeline"""

    def __init__(self):
        self.model = None
        self._lock = threading.Lock()
        self._health_status = {"status": "initializing"}
        self._load_model_with_retry()

    def _load_model_with_retry(self):
        """Load the model with retry mechanism and exponential backoff"""
        delay = MODEL_RETRY_DELAY
        for attempt in range(1, MODEL_RETRIES + 1):
            with METRICS['model_load_duration'].time():
                with self._lock:
                    try:
                        logger.info(f"Attempting to load model from: {config.model.model_path}")
                        if not Path(config.model.model_path).exists():
                            raise FileNotFoundError(f"Model file not found at: {config.model.model_path}")
                        self.model = joblib.load(config.model.model_path)
                        self._verify_model()
                        self._health_status = {
                            "status": "ready",
                            "last_loaded": datetime.now(UTC).isoformat()
                        }
                        logger.info(f"Model loaded successfully from: {config.model.model_path}")
                        return
                    except Exception as load_error:
                        error_msg = f"{type(load_error).__name__}: {str(load_error)}"
                        self._health_status = {
                            "status": "error",
                            "error": error_msg
                        }
                        logger.error(f"Model loading failed (attempt {attempt}/{MODEL_RETRIES}): {error_msg}")
            if attempt < MODEL_RETRIES:
                sleep(delay)
                delay *= 2

        raise ModelLoadError("Failed to load model after all retries")

    def _verify_model(self):
        """Validate the loaded model"""
        if not hasattr(self.model, 'predict'):
            raise ModelValidationError("Invalid model: 'predict' method not found")

        try:
            test_input = np.zeros((1, config.model.n_features))
            _ = self.model.predict(test_input)
        except Exception as validation_error:
            raise ModelValidationError(f"Model validation error: {str(validation_error)}")

    @lru_cache(maxsize=CACHE_SIZE)
    def _cached_predict(self, data_tuple: tuple) -> np.ndarray:
        """Perform cached prediction for improved performance"""
        return self.model.predict(np.array(data_tuple))

    def predict(self, data: np.ndarray) -> np.ndarray:
        """Perform thread-safe prediction"""
        if not self.is_ready():
            raise ModelNotReadyError("Model not ready yet")

        with self._lock:
            with METRICS['prediction_duration'].time():
                try:
                    # Validate input data
                    if not isinstance(data, np.ndarray):
                        data = np.array(data)

                    if data.shape[1] != config.model.n_features:
                        raise ValueError(f"Wrong number of features: {data.shape[1]}")

                    # Handle NaN values
                    if np.any(np.isnan(data)):
                        data = np.nan_to_num(data, nan=config.nan_replacement)

                    # Check input value range
                    if np.any((data < config.model.input_validation["min_value"]) |
                              (data > config.model.input_validation["max_value"])):
                        raise ValueError("Input values out of valid range")

                    # Perform cached prediction
                    return self._cached_predict(tuple(map(tuple, data)))
                except Exception as prediction_error:
                    logger.error(f"Prediction error: {str(prediction_error)}")
                    raise PredictionError(str(prediction_error))

    def is_ready(self) -> bool:
        """Check if the model is ready for predictions"""
        return self.model is not None and hasattr(self.model, 'predict')

    def get_health_status(self) -> dict:
        """Retrieve the health status of the model"""
        return self._health_status

def create_app() -> Flask:
    """Create and configure the Flask application with improved Swagger support"""
    # Use a simpler app name to avoid potential shadowing issues
    app = Flask(__name__)

    # Enhanced Swagger configuration for better compatibility
    app.config['SWAGGER'] = {
        'title': 'ArtukML API',
        'version': '3.0',
        'description': 'Production ML Pipeline API',
        'termsOfService': 'http://example.com/terms/',
        'contact': {'name': 'API Support', 'email': 'support@example.com'},
        'swagger_ui': True  # Ensure Swagger UI is enabled
    }
    Swagger(app)  # Initialize Swagger with the app

    # Initialize the ML Pipeline
    try:
        pipeline = MLPipeline()
    except ModelLoadError as load_error:
        logger.critical(f"Application startup error: {str(load_error)}")
        raise

    # Add security headers to responses with relaxed CSP for Swagger UI
    @app.after_request
    def add_security_headers(response):
        headers = {
            'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'no-referrer'
        }
        for key, value in headers.items():
            response.headers[key] = value
        return response

    # Configure rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[config.rate_limit]
    )

    # JWT validation function
    def verify_jwt(token: str) -> dict:
        """Validate JWT token"""
        try:
            return jwt.decode(
                token,
                config.security.jwt_secret,
                algorithms=[config.security.jwt_algorithm]
            )
        except Exception as auth_error:
            logger.warning(f"Token validation error: {str(auth_error)}")
            raise ValueError("Invalid token")

    # Authentication decorator
    def auth_required(roles: List[str] = None):
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                if not config.enable_auth:
                    return f(*args, **kwargs)

                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify(error="Authorization token required"), 401

                try:
                    token = auth_header.split(' ')[1]
                    claims = verify_jwt(token)

                    if roles and not any(role in claims.get('roles', []) for role in roles):
                        return jsonify(error="Insufficient permissions"), 403

                    return f(*args, **kwargs)
                except ValueError as validation_error:
                    return jsonify(error=str(validation_error)), 401
                except Exception as auth_error:
                    logger.error(f"Authentication error: {str(auth_error)}")
                    return jsonify(error="Authentication error"), 500

            return wrapped
        return decorator

    # Root endpoint (optional, for welcome message)
    @app.route('/')
    def index():
        """Return a simple welcome message for the root URL"""
        return jsonify({
            "message": "Welcome to ArtukML Pipeline API! Use /api/v1/health or /api/v1/predict for endpoints.",
            "documentation": "http://127.0.0.1:5000/apidocs/"  # Swagger documentation URL
        })

    # Ignore favicon requests to avoid 404 in logs
    @app.route('/favicon.ico')
    def favicon():
        """Ignore favicon requests to avoid 404 errors in logs"""
        return '', 204  # No content, successful response

    # Global error handler
    @app.errorhandler(Exception)
    def handle_error(error):
        if isinstance(error, MLAPIException):
            code = error.status_code
            error_type = error.__class__.__name__
        elif isinstance(error, HTTPException):
            code = error.code
            error_type = 'http_error'
        else:
            code = 500
            error_type = 'internal_error'

        message = str(error)
        METRICS['errors_total'].labels(type=error_type).inc()

        logger.error(f"Request error ({error_type}): {message}")
        return jsonify(error=message, type=error_type), code

    # Health check endpoint
    @app.route('/api/v1/health')
    @swag_from({
        'responses': {
            200: {
                'description': 'System health status'
            }
        }
    })
    def health():
        """Return the health status of the system"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(UTC).isoformat(),
            'model': pipeline.get_health_status()
        })

    # Metrics endpoint
    @app.route('/api/v1/metrics')
    def metrics():
        """Return Prometheus metrics"""
        from prometheus_client import generate_latest
        return generate_latest()

    # Prediction request model
    class PredictionRequest(BaseModel):
        """Schema for prediction request data"""
        data: List[List[float]]

        @classmethod
        def validate_data(cls, value: List[List[float]]) -> List[List[float]]:
            """Validate prediction request data"""
            if not value:
                raise ValueError("Empty data sent")
            return value

    # Prediction endpoint
    @app.route('/api/v1/predict', methods=['POST'])
    @swag_from({
        'parameters': [{
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': PredictionRequest.model_json_schema()
        }],
        'responses': {
            200: {
                'description': 'Prediction results'
            }
        }
    })
    @auth_required(roles=config.allowed_roles)
    @limiter.limit(config.rate_limit)
    def predict():
        """Handle prediction requests"""
        with METRICS['request_duration'].labels('predict').time():
            try:
                if not request.is_json:
                    raise ValueError("JSON data required")

                data = request.get_json()
                if not data:
                    raise ValueError("Empty request sent")

                validated_data = PredictionRequest(**data)
                predictions = pipeline.predict(np.array(validated_data.data))

                return jsonify({
                    'predictions': predictions.tolist(),
                    'timestamp': datetime.now(UTC).isoformat()
                })
            except ValidationError as validation_error:
                raise ModelValidationError(str(validation_error))

    return app

if __name__ == '__main__':
    app = create_app()  # Use the app directly, avoiding shadowing

    ssl_context = None
    if config.ssl_cert and config.ssl_key:
        ssl_context = (config.ssl_cert, config.ssl_key)

    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', '5000')),
        debug=DEBUG,
        use_reloader=False,
        ssl_context=ssl_context
    )