#!/usr/bin/env python3
"""
Evrmore Accounts API Application

This module initializes the Flask application for the Evrmore Accounts API.
"""
import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager

# Import API components
from evrmore_accounts.api.auth import auth_blueprint
from evrmore_accounts.api.user import user_blueprint
from evrmore_accounts.api.health import health_blueprint
from evrmore_accounts.api.twofa import twofa_blueprint

# Import error handlers and security components
from evrmore_accounts.api.errors import init_error_handlers
from evrmore_accounts.server_security import init_security

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("evrmore_accounts")

def create_app(test_config=None):
    """Create and configure the Flask application
    
    Args:
        test_config: Optional test configuration
        
    Returns:
        Configured Flask application
    """
    # Create Flask app
    app = Flask(__name__, instance_relative_config=True)
    
    # Check if we're in testing mode
    testing = os.environ.get("TESTING", "").lower() in ("true", "1", "yes")
    
    # Default configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-key-change-in-production"),
        JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY", "jwt-secret-change-in-production"),
        JWT_ACCESS_TOKEN_EXPIRES=3600,  # 1 hour
        JWT_ALGORITHM="HS256",
        DEBUG=os.environ.get("DEBUG", "false").lower() == "true",
        RATE_LIMIT_GLOBAL=int(os.environ.get("RATE_LIMIT_GLOBAL", "100")),
        RATE_LIMIT_AUTH=int(os.environ.get("RATE_LIMIT_AUTH", "5")),
        RATE_LIMIT_CHALLENGE=int(os.environ.get("RATE_LIMIT_CHALLENGE", "10")),
        RATE_LIMIT_USER=int(os.environ.get("RATE_LIMIT_USER", "30")),
        TESTING=testing
    )
    
    # Load test config if provided
    if test_config:
        app.config.update(test_config)
    
    # If in testing mode, set stricter rate limits to make rate limiting more detectable
    if testing:
        app.config.update({
            "RATE_LIMIT_GLOBAL": 10,  # Much stricter for tests
            "RATE_LIMIT_AUTH": 5,     # Strict enough to be detected in tests
            "RATE_LIMIT_CHALLENGE": 5, # Strict enough to be detected in tests  
            "RATE_LIMIT_USER": 10,    # Strict enough to be detected in tests
            "DEBUG": True
        })
        logger.info("Running in TEST mode with stricter rate limits")
    
    # Initialize CORS
    CORS(app, supports_credentials=True)
    
    # Initialize JWT
    jwt = JWTManager(app)
    
    # Initialize security components
    security = init_security(app)
    app.security = security
    
    # Initialize custom error handlers
    init_error_handlers(app)
    
    # Register token callbacks for JWT
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        session_manager = app.security["session_manager"]
        return session_manager.is_token_revoked(jti)
    
    # Register blueprints
    app.register_blueprint(auth_blueprint, url_prefix="/api/auth")
    app.register_blueprint(user_blueprint, url_prefix="/api")
    app.register_blueprint(health_blueprint, url_prefix="/api")
    app.register_blueprint(twofa_blueprint, url_prefix="/api/auth/2fa")
    
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=app.config["DEBUG"], host="0.0.0.0", port=5000)

def main():
    """
    Command line entry point for running the application.
    This function is referenced in setup.py's entry_points.
    """
    app = create_app()
    
    # Get host and port from environment variables, with defaults
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    
    app.run(debug=debug, host=host, port=port) 