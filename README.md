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

## Installation

```bash
pip3 install evrmore-accounts
```

## Running the API Server

### Using Gunicorn (Recommended for Production)

```bash
# Install gunicorn if not already installed
pip3 install gunicorn

# Run with the provided script
./run_gunicorn.sh

# Or manually
gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 wsgi:app
```

### Using Flask Development Server (Development Only)

```bash
# Set environment variables
export FLASK_APP=evrmore_accounts.app:create_app
export FLASK_ENV=development

# Run the development server
flask run
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