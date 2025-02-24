# ArtukML Pipeline 2025

A production-ready Machine Learning Pipeline API built with Flask, designed for secure, scalable, and efficient model serving in enterprise-grade applications.

## 🌟 Features

- **Secure Model Serving**: JWT-based authentication with role-based access control for enhanced security.
- **Performance Optimization**: LRU caching for predictions, connection pooling, and efficient resource management.
- **Real-Time Monitoring**: Integrated Prometheus metrics for monitoring request latency, prediction performance, and errors.
- **API Documentation**: Interactive Swagger/OpenAPI documentation via Flasgger for easy API exploration and testing.
- **Robust Error Handling**: Comprehensive error handling and logging with rotating file handlers for production reliability.
- **Rate Limiting**: Configurable rate limiting per endpoint to prevent abuse and ensure fair usage.
- **Security Best Practices**: Implementation of security headers (e.g., CSP, HSTS), input validation, and SSL/TLS support for secure communication.
- **Containerization**: Full Docker support with `Dockerfile` and `docker-compose.yml` for easy deployment and scalability.
- **CI/CD Integration**: Automated testing and deployment with GitHub Actions for continuous integration.
- **Health Monitoring**: Built-in health check endpoint for system status verification.
- **Input Validation**: Pydantic-based request validation for robust data handling.
- **NaN Handling**: Configurable handling of missing values (NaN) in prediction inputs.

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- `pip` package manager
- Docker (optional for containerized deployment)
- A trained machine learning model saved as a `joblib` file

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/muratyigitartuk/artukml-pipeline.git
   cd artukml-pipeline
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure the application:
   - Copy config.yaml.example to config.yaml (create config.yaml.example if not present).
   - Update config.yaml with your settings:
     - Set model.model_path to the correct path of your joblib model file (e.g., model/model.joblib).
     - Configure a secure security.jwt_secret (minimum 32 characters, never use "your-secret-key" in production; store in environment variables or GitHub Secrets).
     - Adjust rate_limit, n_features, and other settings as needed.

### Running the Application

**Using Python**
```bash
  python app.py
```

**Using Docker**
```bash
  docker build -t artukml-pipeline .
  docker run -p 5000:5000 artukml-pipeline
```

**Using Docker Compose**
```bash
  docker-compose up
```

To stop and remove containers, use:
```bash
  docker-compose down
```

Access the API at http://127.0.0.1:5000/ or use the Swagger UI at http://127.0.0.1:5000/apidocs/ for documentation.

## 📚 API Documentation

### Endpoints

- **GET /**: Returns a welcome message and links to API endpoints and documentation.
- **GET /api/v1/health**: Checks the system's health status and model readiness (no authentication required).
- **POST /api/v1/predict**: Handles prediction requests, requiring a JSON body and JWT authentication. Example body:
  ```json
  {
    "data": [[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]]
  }
  ```
  where n_features is set to 10 in config.yaml.
- **GET /api/v1/metrics**: Exposes Prometheus metrics for monitoring.
- **GET /apidocs/**: Provides interactive Swagger UI documentation.

### Authentication

The API uses JWT tokens for authentication (required for /api/v1/predict). Include the token in the Authorization header:

```bash
curl -X POST http://localhost:5000/api/v1/predict \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"data": [[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]]}'
```

To generate a JWT token, use the JWT/generate_token.py script or a similar tool, ensuring the JWT_SECRET matches your config.yaml or environment variable settings (e.g., stored in GitHub Secrets). Example token generation:

```python
import os
import jwt
secret = os.getenv('JWT_SECRET', 'default-secret')  # Use a secure secret in production
token = jwt.encode({"roles": ["admin"]}, secret, algorithm="HS256")
print(token)
```

## 🔧 Configuration

### Environment Variables

- **FLASK_DEBUG**: Toggles debug mode (default: false for production).
- **CONFIG_PATH**: Path to the configuration file (default: config.yaml).
- **MODEL_RETRIES**: Number of attempts to load the model (default: 3).
- **MODEL_RETRY_DELAY**: Delay between model loading retries in seconds (default: 5).
- **MAX_REQUEST_SIZE**: Maximum request size in bytes (default: 1MB).
- **CACHE_SIZE**: Size of the LRU cache for predictions (default: 1024).
- **JWT_SECRET**: Secret key for JWT token generation and validation (store securely in GitHub Secrets for production).
- **PORT**: Application port (default: 5000).

### Config File (config.yaml)

```yaml
model:
  model_path: "model/model.joblib"  # Path to your trained model
  n_features: 10                  # Number of input features expected by the model
  input_validation:
    min_value: -1e6               # Minimum allowed input value
    max_value: 1e6               # Maximum allowed input value

security:
  jwt_secret: "${JWT_SECRET}"      # Use environment variable for secure secret (e.g., GitHub Secrets)
  jwt_algorithm: "HS256"           # JWT signing algorithm
  token_expire_minutes: 60        # Token expiration time in minutes

allowed_roles:
  - "admin"                       # Allowed roles for authentication
  - "user"

rate_limit: "100/minute"          # Rate limit for API requests
nan_replacement: 0.0              # Value to replace NaN inputs
enable_auth: true                 # Enable/disable authentication
ssl_cert: null                    # Path to SSL certificate (optional)
ssl_key: null                     # Path to SSL key (optional)
```

Note: Never use "default-secret" or "your-secret-key" in production. Use a secure, randomly generated secret stored in environment variables or GitHub Secrets.

## 🔍 Testing

Run the test suite locally:

```bash
  pytest test/
```

Ensure all tests pass, covering health checks, predictions, authentication, error cases, and rate limiting. In the GitHub Actions pipeline, test results are stored in test-results.xml for detailed reporting.

## 📊 Monitoring

The application exposes Prometheus metrics at /api/v1/metrics. Available metrics include:

- http_requests_total: Total HTTP requests, categorized by method, endpoint, and status.
- http_request_duration_seconds: Histogram of request duration in seconds by endpoint.
- prediction_duration_seconds: Summary of model prediction duration in seconds.
- model_load_duration_seconds: Summary of model loading duration in seconds.
- http_errors_total: Total HTTP errors, categorized by error type.

To monitor effectively, configure a Prometheus server to scrape /api/v1/metrics and visualize data with Grafana. Example Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'artukml'
    static_configs:
      - targets: ['localhost:5000']
```

## 🔒 Security Features

- **JWT Authentication**: Secure access with JSON Web Tokens and role-based authorization.
- **Role-Based Access Control (RBAC)**: Limits access based on user roles (admin, user).
- **Rate Limiting**: Prevents abuse with configurable limits per endpoint.
- **Security Headers**: Implements best practices, including Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), and XSS protection.
- **Input Validation**: Ensures data integrity with Pydantic schemas.
- **SSL/TLS Support**: Optional encryption for secure communication.
- **NaN Handling**: Configurable replacement for missing values in predictions.
- **Request Size Limiting**: Prevents oversized requests with configurable limits.

Production Note: Use secure secrets (e.g., JWT_SECRET) in GitHub Secrets or environment variables, and avoid hardcoding sensitive values in config.yaml.

## 📁 Project Structure

```text
artukml-pipeline/
├── .github/              # GitHub-related configurations (e.g., workflows)
├── .gitignore            # Git ignore file
├── .idea/                # IDE configuration (e.g., IntelliJ IDEA)
├── venv/                 # Virtual environment
├── JWT/                  # JWT-related scripts
│   └── generate_token.py # Script to generate JWT tokens
├── model/                # Machine learning model files
│   └── model.joblib      # Trained model file
├── test/                 # Test suite
│   ├── __init__.py       # Package initialization
│   ├── conftest.py       # Pytest fixtures
│   └── test_app.py       # Test cases
├── app.py                # Main application file
├── config.yaml           # Configuration file
├── create_model.py       # Script to create the ML model
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile            # Docker configuration
├── License.txt           # License file
├── ml-api.log           # Application log file
├── README.md             # Project documentation
└── requirements.txt      # Python dependencies
```

## 🤝 Contributing

We welcome contributions to enhance the ArtukML Pipeline! Follow these steps:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/AmazingFeature`.
3. Commit your changes: `git commit -m 'Add some AmazingFeature'` (adhere to PEP 8 style guidelines).
4. Push to the branch: `git push origin feature/AmazingFeature`.
5. Open a Pull Request with a detailed description of your changes, including test cases for new features.

Please ensure code quality, add unit tests, and update documentation as needed.

## 📄 License

This project is licensed under the MIT License - see the License.txt file for details. 

The MIT License permits use, modification, and distribution under certain conditions, making it ideal for open-source collaboration.

## 👤 Author

Murat Yigit Artuk

GitHub | G-Mail (muratyigitartuk0@gmail.com)

## 🙏 Acknowledgments

- Flask and its extensions (e.g., Flasgger 0.9.7, Flask-Limiter) for robust web development.
- Prometheus and Grafana for monitoring solutions.
- scikit-learn and joblib for machine learning support.
- Pydantic for input validation and data modeling.
- All open-source libraries listed in requirements.txt for enabling this project.
- The open-source community for inspiration, tools, and contributions.