# Evrmore Accounts Security Implementation Guide

This document provides instructions for implementing the security improvements recommended in the security audit report.

## Table of Contents

1. [Security Headers](#security-headers)
2. [Advanced Rate Limiting](#advanced-rate-limiting)
3. [JWT Token Security](#jwt-token-security)
4. [Session Management](#session-management)
5. [Two-Factor Authentication Enhancements](#two-factor-authentication-enhancements)
6. [Error Handling Standardization](#error-handling-standardization)
7. [Logging Enhancements](#logging-enhancements)

## Security Headers

The security audit identified missing security headers in API responses. Implementing these headers can significantly improve the security posture of the application.

### Implementation

1. Add the `security_headers.py` module to your project:

```python
# security_headers.py
from typing import Dict, Optional, Callable, Any
from flask import Flask, Response

class SecurityHeadersMiddleware:
    """Middleware to add security headers to all responses"""
    
    def __init__(self, app: Optional[Flask] = None):
        """Initialize the middleware"""
        self.headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Cache-Control': 'no-store, max-age=0',
            'Pragma': 'no-cache'
        }
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize with a Flask application"""
        app.after_request(self.add_security_headers)
    
    def add_security_headers(self, response: Response) -> Response:
        """Add security headers to response"""
        for header, value in self.headers.items():
            response.headers.setdefault(header, value)
        
        return response

def init_security_headers(app: Flask) -> None:
    """Initialize security headers middleware"""
    SecurityHeadersMiddleware(app)
    app.logger.info("Security headers middleware initialized")
```

2. Integrate the security headers middleware with your Flask application:

```python
# evrmore_accounts/app.py
from evrmore_accounts.security_headers import init_security_headers

def create_app(debug: bool = DEBUG) -> Flask:
    # Create app
    app = Flask(__name__)
    
    # Initialize security headers
    init_security_headers(app)
    
    # Other app initialization
    # ...
    
    return app
```

## Advanced Rate Limiting

The security audit recommended enhancing rate limiting to better protect against distributed attacks.

### Implementation

1. Add the `advanced_rate_limiter.py` module to your project:

```python
# See the full implementation in advanced_rate_limiter.py
```

2. Integrate the rate limiter with your Flask application:

```python
# evrmore_accounts/app.py
from evrmore_accounts.advanced_rate_limiter import init_rate_limiter

def create_app(debug: bool = DEBUG) -> Flask:
    # Create app
    app = Flask(__name__)
    
    # Initialize rate limiter
    rate_limiter = init_rate_limiter(app)
    
    # Add custom whitelist/blacklist
    rate_limiter.add_whitelist("127.0.0.1")  # Whitelist local development
    
    # Other app initialization
    # ...
    
    return app
```

## JWT Token Security

Enhance the security of JWT tokens with the following improvements:

### Implementation

1. Update the JWT configuration to use stronger algorithms and shorter expiration times:

```python
# evrmore_accounts/api/server.py

# Configure and initialize Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-jwt-key")
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
app.config["JWT_ALGORITHM"] = "HS256"  # Use HS256 for better performance
app.config["JWT_IDENTITY_CLAIM"] = "sub"
app.config["JWT_HEADER_TYPE"] = "Bearer"
```

2. Add device fingerprinting to tokens:

```python
# evrmore_accounts/api/auth.py

def create_token_for_user(user_id, evrmore_address):
    """Create a new JWT token for a user
    
    Args:
        user_id: User ID
        evrmore_address: Evrmore address
        
    Returns:
        JWT token
    """
    # Get device and request information for fingerprinting
    user_agent = request.headers.get("User-Agent", "")
    ip_address = request.remote_addr
    
    # Create a device fingerprint
    fingerprint = hashlib.sha256(f"{user_agent}:{ip_address}".encode()).hexdigest()
    
    # Create token with user ID, Evrmore address, and fingerprint
    token = create_access_token(
        identity=user_id,
        additional_claims={
            "evrmore_address": evrmore_address,
            "fingerprint": fingerprint,
            "token_type": "access",
            "token_version": 1
        }
    )
    
    return token
```

3. Implement token rotation for long-lived sessions:

```python
# evrmore_accounts/api/auth.py

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh an access token
    
    Returns:
        New access token
    """
    user_id = get_jwt_identity()
    user = auth_controller.get_user_by_id(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 401
    
    # Create a new access token
    new_token = create_token_for_user(user_id, user["evrmore_address"])
    
    return jsonify({
        "token": new_token,
        "user": user
    })
```

## Session Management

Implement centralized session tracking to allow users to view and manage active sessions:

### Implementation

1. Create a session tracking module:

```python
# evrmore_accounts/api/sessions.py

import time
import uuid
from typing import Dict, List, Optional
from flask import request
from flask_jwt_extended import get_jwt

class SessionManager:
    """Session manager for tracking active user sessions"""
    
    def __init__(self, db_conn=None):
        """Initialize session manager"""
        self.db_conn = db_conn
        self.sessions = {}  # In-memory session storage (use DB in production)
    
    def create_session(self, user_id: str, token_jti: str) -> Dict:
        """Create a new session for a user
        
        Args:
            user_id: User ID
            token_jti: JWT token JTI (unique identifier)
            
        Returns:
            Session data
        """
        session_id = str(uuid.uuid4())
        user_agent = request.headers.get("User-Agent", "Unknown")
        ip_address = request.remote_addr or "0.0.0.0"
        
        session = {
            "id": session_id,
            "user_id": user_id,
            "token_jti": token_jti,
            "user_agent": user_agent,
            "ip_address": ip_address,
            "created_at": time.time(),
            "last_active": time.time()
        }
        
        # Store session in memory (or DB in production)
        if user_id not in self.sessions:
            self.sessions[user_id] = []
        self.sessions[user_id].append(session)
        
        return session
    
    def get_sessions(self, user_id: str) -> List[Dict]:
        """Get all active sessions for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of active sessions
        """
        return self.sessions.get(user_id, [])
    
    def update_session_activity(self, token_jti: str) -> bool:
        """Update session last activity time
        
        Args:
            token_jti: JWT token JTI
            
        Returns:
            True if session was updated, False otherwise
        """
        # Search for session with matching JTI
        for user_id, sessions in self.sessions.items():
            for session in sessions:
                if session["token_jti"] == token_jti:
                    session["last_active"] = time.time()
                    return True
        
        return False
    
    def revoke_session(self, user_id: str, session_id: str) -> bool:
        """Revoke a session
        
        Args:
            user_id: User ID
            session_id: Session ID
            
        Returns:
            True if session was revoked, False otherwise
        """
        if user_id not in self.sessions:
            return False
        
        # Filter out the session to revoke
        before_count = len(self.sessions[user_id])
        self.sessions[user_id] = [s for s in self.sessions[user_id] if s["id"] != session_id]
        after_count = len(self.sessions[user_id])
        
        return before_count > after_count
    
    def is_token_revoked(self, token_jti: str) -> bool:
        """Check if a token has been revoked
        
        Args:
            token_jti: JWT token JTI
            
        Returns:
            True if token is revoked, False otherwise
        """
        # Search for session with matching JTI
        for user_id, sessions in self.sessions.items():
            for session in sessions:
                if session["token_jti"] == token_jti:
                    return False
        
        # If no matching session found, token is considered revoked
        return True
```

2. Integrate the session manager with your Flask-JWT-Extended configuration:

```python
# evrmore_accounts/api/server.py

from evrmore_accounts.api.sessions import SessionManager

# Create session manager
session_manager = SessionManager()

# Configure and initialize Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-jwt-key")
# Other JWT config...

jwt = JWTManager(app)

# Register JWT callbacks
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return session_manager.is_token_revoked(jti)

@app.after_request
def update_session_activity(response):
    if response.status_code < 400:
        try:
            # Get current token JTI
            jwt_data = get_jwt()
            jti = jwt_data["jti"]
            session_manager.update_session_activity(jti)
        except:
            # Not an authenticated request
            pass
    return response
```

3. Add endpoints for viewing and managing sessions:

```python
# evrmore_accounts/api/auth.py

@auth_bp.route("/sessions", methods=["GET"])
@jwt_required()
def get_active_sessions():
    """Get all active sessions for the current user"""
    user_id = get_jwt_identity()
    sessions = session_manager.get_sessions(user_id)
    
    # Format sessions for response
    formatted_sessions = []
    for session in sessions:
        formatted_sessions.append({
            "id": session["id"],
            "user_agent": session["user_agent"],
            "ip_address": session["ip_address"],
            "created_at": session["created_at"],
            "last_active": session["last_active"]
        })
    
    return jsonify({"sessions": formatted_sessions})

@auth_bp.route("/sessions/<session_id>", methods=["DELETE"])
@jwt_required()
def revoke_session(session_id):
    """Revoke a session"""
    user_id = get_jwt_identity()
    
    # Check if trying to revoke current session
    current_token = get_jwt()
    current_jti = current_token["jti"]
    
    # Find if session_id matches current session
    sessions = session_manager.get_sessions(user_id)
    is_current_session = any(s["id"] == session_id and s["token_jti"] == current_jti for s in sessions)
    
    # Revoke the session
    success = session_manager.revoke_session(user_id, session_id)
    
    if not success:
        return jsonify({"error": "Session not found"}), 404
    
    # If revoking current session, return special status
    if is_current_session:
        return jsonify({
            "success": True, 
            "message": "Current session revoked, please log in again",
            "current_session_revoked": True
        })
    
    return jsonify({"success": True, "message": "Session revoked"})
```

## Two-Factor Authentication Enhancements

Enhance the 2FA implementation with backup codes and additional security:

### Implementation

1. Add backup code generation to the TOTP setup process:

```python
# evrmore_accounts/api/twofa.py

import random
import string

def generate_backup_codes(count=10, length=8):
    """Generate backup codes for 2FA recovery
    
    Args:
        count: Number of codes to generate
        length: Length of each code
        
    Returns:
        List of backup codes
    """
    codes = []
    for _ in range(count):
        # Generate a random code using digits and uppercase letters
        # (avoiding similar-looking characters)
        chars = string.digits + string.ascii_uppercase
        chars = chars.replace('0', '').replace('O', '').replace('1', '').replace('I', '')
        code = ''.join(random.choice(chars) for _ in range(length))
        
        # Format as 2 groups for readability
        formatted_code = f"{code[:4]}-{code[4:]}"
        codes.append(formatted_code)
    
    return codes

def enable_totp(self, user_id: str, code: str) -> Dict:
    """Enable TOTP for a user
    
    Args:
        user_id: User ID
        code: TOTP code to verify
        
    Returns:
        Result with success status and backup codes
    """
    # Verify the code first
    if not self.verify_totp_code(user_id, code):
        return {"success": False, "message": "Invalid TOTP code"}
    
    # Generate backup codes
    backup_codes = generate_backup_codes()
    
    # Store hashed backup codes
    hashed_codes = []
    for code in backup_codes:
        hashed_code = self._hash_code(code)
        hashed_codes.append(hashed_code)
    
    # Update user's 2FA settings in the database
    # ...
    
    return {
        "success": True,
        "backup_codes": backup_codes,
        "message": "TOTP enabled successfully"
    }
```

2. Add support for backup code validation:

```python
# evrmore_accounts/api/twofa.py

def verify_backup_code(self, user_id: str, code: str) -> bool:
    """Verify a backup code
    
    Args:
        user_id: User ID
        code: Backup code to verify
        
    Returns:
        True if code is valid, False otherwise
    """
    # Normalize the code (remove spaces, dashes, etc.)
    normalized_code = code.replace("-", "").replace(" ", "").upper()
    
    # Get the user's hashed backup codes from the database
    # ...
    
    # Check if the code matches any of the backup codes
    for hashed_code in user["backup_codes"]:
        if self._verify_code(normalized_code, hashed_code):
            # Mark the code as used (remove from list)
            # ...
            return True
    
    return False
```

## Error Handling Standardization

Standardize error responses to avoid leaking implementation details:

### Implementation

1. Create a standardized error response module:

```python
# evrmore_accounts/api/errors.py

from flask import jsonify
from werkzeug.exceptions import HTTPException

def init_error_handlers(app):
    """Initialize error handlers for the Flask application"""
    
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({
            "error": "bad_request",
            "message": str(e) or "Bad request"
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({
            "error": "unauthorized",
            "message": "Authentication required"
        }), 401
    
    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({
            "error": "forbidden",
            "message": "You don't have permission to access this resource"
        }), 403
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            "error": "not_found",
            "message": "The requested resource was not found"
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({
            "error": "method_not_allowed",
            "message": "The method is not allowed for this resource"
        }), 405
    
    @app.errorhandler(429)
    def too_many_requests(e):
        return jsonify({
            "error": "too_many_requests",
            "message": "Too many requests, please try again later"
        }), 429
    
    @app.errorhandler(500)
    def server_error(e):
        return jsonify({
            "error": "server_error",
            "message": "An internal server error occurred"
        }), 500
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        return jsonify({
            "error": e.name.lower().replace(" ", "_"),
            "message": e.description
        }), e.code
    
    @app.errorhandler(Exception)
    def handle_generic_exception(e):
        # Log the actual error for debugging
        app.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
        
        # Return a generic error response to the client
        return jsonify({
            "error": "server_error",
            "message": "An unexpected error occurred"
        }), 500
```

2. Integrate the error handlers with your Flask application:

```python
# evrmore_accounts/app.py
from evrmore_accounts.api.errors import init_error_handlers

def create_app(debug: bool = DEBUG) -> Flask:
    # Create app
    app = Flask(__name__)
    
    # Initialize error handlers
    init_error_handlers(app)
    
    # Other app initialization
    # ...
    
    return app
```

## Logging Enhancements

Improve logging for security events and forensic analysis:

### Implementation

1. Create an enhanced logging module:

```python
# evrmore_accounts/logging.py

import os
import logging
import json
from datetime import datetime
from flask import request, g
from uuid import uuid4

class SecurityLogger:
    """Enhanced logger for security events"""
    
    def __init__(self, app=None, log_file=None):
        """Initialize security logger"""
        self.logger = logging.getLogger("evrmore_accounts.security")
        
        # Create a file handler if log_file is provided
        if log_file:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with a Flask application"""
        # Set up request ID
        @app.before_request
        def set_request_id():
            g.request_id = str(uuid4())
        
        # Log all requests
        @app.after_request
        def log_request(response):
            self.log_request(request, response)
            return response
    
    def log_request(self, req, response):
        """Log a request"""
        # Skip logging for health checks and static files
        if req.path.endswith('/health') or req.path.startswith('/static/'):
            return
        
        # Get client information
        ip = req.headers.get('X-Forwarded-For', req.remote_addr)
        user_agent = req.headers.get('User-Agent', '')
        
        # Get user ID if authenticated
        user_id = getattr(g, 'user_id', None)
        
        # Get request details
        method = req.method
        path = req.path
        status_code = response.status_code
        
        # Create log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': getattr(g, 'request_id', str(uuid4())),
            'ip': ip,
            'user_agent': user_agent,
            'user_id': user_id,
            'method': method,
            'path': path,
            'status_code': status_code,
            'response_time_ms': getattr(g, 'response_time_ms', 0)
        }
        
        # Log as JSON for easier parsing
        self.logger.info(json.dumps(log_entry))
    
    def log_auth_event(self, event_type, user_id=None, evrmore_address=None, details=None):
        """Log an authentication event
        
        Args:
            event_type: Type of auth event (login, logout, etc.)
            user_id: User ID (if available)
            evrmore_address: Evrmore address (if available)
            details: Additional event details
        """
        # Get client information
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        # Create log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': getattr(g, 'request_id', str(uuid4())),
            'event_type': event_type,
            'ip': ip,
            'user_agent': user_agent,
            'user_id': user_id,
            'evrmore_address': evrmore_address
        }
        
        # Add additional details if provided
        if details:
            log_entry['details'] = details
        
        # Log as JSON for easier parsing
        self.logger.info(json.dumps(log_entry))
```

2. Integrate the security logger with your authentication controller:

```python
# evrmore_accounts/api/auth.py
from evrmore_accounts.logging import SecurityLogger

# Initialize security logger
security_logger = SecurityLogger()

def authenticate(evrmore_address, challenge, signature):
    """Authenticate a user with a signed challenge
    
    Args:
        evrmore_address: Evrmore address
        challenge: Challenge text
        signature: Signature of the challenge
        
    Returns:
        Authentication result
    """
    try:
        # Verify the signature
        # ...
        
        # Log the authentication attempt
        security_logger.log_auth_event(
            event_type='login_attempt',
            evrmore_address=evrmore_address,
            details={'success': False, 'reason': 'Invalid signature'}
        )
        
        # Return error if verification fails
        if not verified:
            return {"success": False, "message": "Invalid signature"}
        
        # Get or create user
        user = get_or_create_user(evrmore_address)
        
        # Create token
        token = create_token_for_user(user["id"], evrmore_address)
        
        # Log the successful login
        security_logger.log_auth_event(
            event_type='login_success',
            user_id=user["id"],
            evrmore_address=evrmore_address
        )
        
        return {
            "success": True,
            "token": token,
            "user": user
        }
        
    except Exception as e:
        # Log the error
        security_logger.log_auth_event(
            event_type='login_error',
            evrmore_address=evrmore_address,
            details={'error': str(e)}
        )
        
        # Re-raise the exception to be handled by the error handler
        raise
```

## Conclusion

By implementing these security improvements, you can significantly enhance the security posture of the Evrmore Accounts backend. These changes address the key vulnerabilities identified in the security audit and follow industry best practices for secure API development.

Remember to test each change thoroughly in a development environment before deploying to production. Some of these changes may require database schema updates or other infrastructure changes.

For additional security enhancements, consider implementing:

1. API key management for third-party integrations
2. WebAuthn (FIDO2) support for hardware security keys
3. Decentralized identity integration
4. Regular security scanning and penetration testing 