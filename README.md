# Evrmore Accounts

A RESTful API service for Evrmore blockchain-based authentication.

## Overview

Evrmore Accounts provides a secure REST API for authenticating users with Evrmore blockchain wallets. This is a backend-only service with no frontend components.

Key features:
- Secure blockchain-based authentication using Evrmore wallet signatures
- Two-factor authentication support (TOTP and WebAuthn)
- JWT-based token authentication with enhanced security
- User profile management
- High-performance API built with Flask and Gunicorn
- Advanced security features including rate limiting and security headers

## Security Features

Evrmore Accounts includes comprehensive security features:

- **Security Headers**: Protection against XSS, clickjacking, and other web vulnerabilities
- **Rate Limiting**: Advanced IP-based rate limiting with whitelist/blacklist support
- **Session Management**: Tracking and management of active user sessions
- **Enhanced JWT Security**: Device fingerprinting and token revocation
- **Two-Factor Authentication**: TOTP and WebAuthn (FIDO2) support with backup codes
- **Standardized Error Handling**: Consistent error responses with appropriate status codes
- **Enhanced Logging**: Detailed logging of security events for forensic analysis

## Project Structure

```
evrmore-accounts/
│── evrmore_accounts/     # Main package (source code)
│   ├── __init__.py       # Package initialization
│   ├── app.py            # Main entry point
│   ├── api/              # API endpoints
│   ├── database.py       # Database models & management
│   ├── server_security.py # Security & rate-limiting features
│   ├── healthcheck.py    # Health check utilities
│   ├── advanced_rate_limiter.py # Rate limiting implementation
│   ├── security_headers.py # Security headers middleware
│   └── data/             # Data files
│
│── config/               # Configuration files
│   ├── config.py         # Configuration classes
│   └── .env.example      # Example environment variables
│
│── tests/                # Test files
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── security/         # Security tests
│
│── docs/                 # Documentation
│   ├── implementation/   # Implementation documentation
│   └── API_REFERENCE.md  # API reference
│
│── scripts/              # Helper scripts
│   ├── run.py            # Development server runner
│   └── run_gunicorn.sh   # Production server runner
│
│── setup.py              # Package setup script
│── setup.cfg             # Package configuration
│── pyproject.toml        # Project configuration
│── MANIFEST.in           # Package manifest
│── Makefile              # Build automation
│── wsgi.py               # WSGI entry point
└── LICENSE               # License file
```

For a detailed explanation of the project structure and components, see [Project Structure Documentation](docs/PROJECT_STRUCTURE.md).

## Installation

You can install Evrmore Accounts directly from the repository:

```bash
# Clone the repository
git clone https://github.com/manticoretechnologies/evrmore-accounts.git
cd evrmore-accounts

# Install the package in development mode
pip3 install -e .

# Or install with development dependencies
pip3 install -e ".[dev]"
```

Alternatively, you can use the provided Makefile:

```bash
# Install the package
make install

# Install with development dependencies
make dev-setup
```

## Running the API Server

### Using the Makefile (Recommended)

The provided Makefile simplifies common development tasks:

```bash
# Run the development server
make run

# Run the development server with debug mode
make dev

# Run with Gunicorn (production)
make run-gunicorn

# Run tests
make test          # Run integration tests
make test-unit     # Run unit tests
make test-security # Run security tests
make test-all      # Run all tests

# Check server health
make healthcheck
```

### Using Gunicorn (Recommended for Production)

```bash
# Run with the provided script
./run_gunicorn.sh

# Or with environment variables
HOST=0.0.0.0 PORT=8000 WORKERS=8 TIMEOUT=120 ./run_gunicorn.sh
```

### Using Flask Development Server (Development Only)

```bash
# Run the development server directly
python3 -m evrmore_accounts.app

# Or with environment variables
DEBUG=true HOST=0.0.0.0 PORT=5000 python3 -m evrmore_accounts.app
```

## Running Tests

```bash
# Run integration tests
python3 -m tests.integration.test_backend

# Run unit tests
python3 -m tests.unit.db_test

# Run security tests
python3 -m tests.security.test_security

# Check server health
python3 -m evrmore_accounts.healthcheck
```

## API Endpoints

All API endpoints are prefixed with `/api`.

### Authentication

- `POST /api/challenge` - Generate a challenge for authentication
- `POST /api/authenticate` - Verify signature and authenticate
- `GET /api/validate` - Validate an existing token
- `POST /api/logout` - Log out (invalidate token)

### User Management

- `GET /api/user` - Get the authenticated user's profile
- `PUT /api/user` - Update user profile
- `POST /api/user/backup-address` - Add a backup Evrmore address

### Two-Factor Authentication (2FA)

- `POST /api/auth/2fa/totp/setup` - Set up TOTP-based 2FA
- `POST /api/auth/2fa/totp/verify` - Verify a TOTP code
- `POST /api/auth/2fa/totp/enable` - Enable TOTP for the account
- `POST /api/auth/2fa/totp/disable` - Disable TOTP for the account
- `GET /api/auth/2fa/totp/status` - Get TOTP status
- `GET /api/auth/2fa/status` - Get overall 2FA status
- `GET /api/auth/2fa/recovery-codes` - Get recovery codes for 2FA
- `POST /api/auth/2fa/recovery-codes/verify` - Verify a recovery code

### WebAuthn (FIDO2) Support

- `POST /api/auth/2fa/webauthn/register-options` - Get registration options for WebAuthn
- `POST /api/auth/2fa/webauthn/register-verify` - Verify WebAuthn registration
- `POST /api/auth/2fa/webauthn/authenticate-options` - Get authentication options for WebAuthn
- `POST /api/auth/2fa/webauthn/authenticate-verify` - Verify WebAuthn authentication
- `GET /api/auth/2fa/webauthn/credentials` - Get registered WebAuthn credentials
- `DELETE /api/auth/2fa/webauthn/credentials/{credential_id}` - Remove a WebAuthn credential

### Session Management

- `GET /api/sessions` - Get all active sessions for the current user
- `DELETE /api/sessions/{session_id}` - Revoke a specific session
- `DELETE /api/sessions` - Revoke all sessions except the current one

### Health Check

- `GET /api/health` - Check API health status

## Configuration

Configuration is managed through environment variables:

```
# Required
JWT_SECRET_KEY=your-secure-jwt-secret

# Optional
DEBUG=false
PORT=5000
HOST=0.0.0.0
WORKERS=4
TIMEOUT=120
RATE_LIMIT_GLOBAL=100  # Requests per minute globally
RATE_LIMIT_AUTH=5      # Requests per minute for auth endpoints
RATE_LIMIT_CHALLENGE=10 # Requests per minute for challenge endpoint
RATE_LIMIT_USER=30     # Requests per minute for user endpoints
```

## Security Testing

The repository includes a security testing script that checks for proper implementation of security features:

```bash
python3 test_security.py --url http://localhost:5000
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

- Manticore Technologies - [manticore.technology](https://manticore.technology)
- GitHub: [github.com/manticoretechnologies](https://github.com/manticoretechnologies)
- Email: [dev@manticore.technology](mailto:dev@manticore.technology) 