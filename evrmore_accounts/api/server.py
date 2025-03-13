#!/usr/bin/env python3
"""
Evrmore Accounts API Server

This module provides a Flask-based API server for the Evrmore Accounts service.
"""
import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from evrmore_authentication.exceptions import AuthenticationError
from flask_jwt_extended import JWTManager

from .auth import EvrmoreAccountsAuth, init_auth
from evrmore_accounts import __version__

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('evrmore_accounts.server')

class AccountsServer:
    """Evrmore Accounts API Server"""
    
    def __init__(self, debug: bool = False):
        """
        Initialize the API server.
        
        Args:
            debug: Enable debug mode
        """
        self.debug = debug
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # Initialize Flask app
        self.app = Flask(__name__)
        CORS(self.app)

        # Configure and initialize Flask-JWT-Extended
        self.app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-jwt-key")
        self.app.config["JWT_TOKEN_LOCATION"] = ["headers"]
        self.app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
        self.jwt = JWTManager(self.app)
        
        # Initialize auth module
        self.auth, auth_blueprint = init_auth(debug=debug)
        
        # Register the auth blueprint
        self.app.register_blueprint(auth_blueprint, url_prefix='/api/auth')
        
        # Add health check endpoints 
        @self.app.route('/health', methods=['GET', 'OPTIONS'])
        def health_check():
            """Health check endpoint to verify API availability."""
            # Add proper CORS headers for direct health endpoint
            if request.method == 'OPTIONS':
                response = self.app.make_default_options_response()
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
                response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
                return response
                
            try:
                return jsonify({
                    "status": "ok",
                    "version": __version__,
                    "service": "evrmore-accounts"
                }), 200
            except Exception as e:
                logger.error(f"Error in health check: {str(e)}")
                return jsonify({
                    "status": "error",
                    "error": str(e)
                }), 500
        
        # Also add a health endpoint at /api/health for consistency
        @self.app.route('/api/health', methods=['GET', 'OPTIONS'])
        def api_health_check():
            """Health check endpoint to verify API availability (with /api prefix)."""
            # Add proper CORS headers for API health endpoint
            if request.method == 'OPTIONS':
                response = self.app.make_default_options_response()
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
                response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
                return response
                
            try:
                return jsonify({
                    "status": "ok",
                    "version": __version__,
                    "service": "evrmore-accounts"
                }), 200
            except Exception as e:
                logger.error(f"Error in API health check: {str(e)}")
                return jsonify({
                    "status": "error",
                    "error": str(e)
                }), 500
        
        logger.info("Health check endpoints registered at /health and /api/health")
        
        # Register API routes
        self._register_routes()
        
        logger.info("Evrmore Accounts API Server initialized")
    
    def _record_login_metrics(self, user_id, ip_address, user_agent, success, error=None):
        """
        Record login metrics for analysis and security monitoring.
        
        Args:
            user_id: The user ID or None for failed attempts
            ip_address: IP address of the client
            user_agent: User agent string of the client
            success: Whether the login was successful
            error: Error message if login failed
        """
        timestamp = datetime.utcnow().isoformat()
        metrics = {
            "timestamp": timestamp,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": success
        }
        
        if error:
            metrics["error"] = error
        
        # In a production environment, these metrics would be stored in a database
        # or sent to a monitoring/analytics service.
        # For now, we'll just log them.
        
        if success:
            logger.info(f"Login metrics: User {user_id} successfully logged in from {ip_address} at {timestamp}")
        else:
            logger.warning(f"Login metrics: Failed login attempt from {ip_address} at {timestamp}, error: {error}")
        
        # You could extend this to include:
        # - Geographic location based on IP
        # - Device type detection from User-Agent
        # - Counts of successful/failed logins per user/IP
        # - Time-based analytics (logins per hour/day)
        
        return metrics
    
    def _register_routes(self) -> None:
        """Register API routes with Flask."""
        
        # Challenge generation endpoint
        @self.app.route('/api/challenge', methods=['POST'])
        def challenge():
            try:
                data = request.json
                if not data or 'evrmore_address' not in data:
                    logger.warning("Missing evrmore_address in challenge request")
                    return jsonify({
                        "error": "Missing evrmore_address parameter"
                    }), 400
                
                evrmore_address = data['evrmore_address']
                expire_minutes = int(data.get('expire_minutes', 10))
                
                # Generate challenge
                result = self.auth.generate_challenge(
                    evrmore_address=evrmore_address,
                    expire_minutes=expire_minutes
                )
                
                # Format expiration time
                if result.get('expires_at'):
                    result['expires_at'] = result['expires_at'].isoformat()
                
                return jsonify(result)
            except Exception as e:
                logger.error(f"Error in challenge endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Authentication endpoint
        @self.app.route('/api/authenticate', methods=['POST'])
        def authenticate():
            try:
                data = request.json
                if not data or not all(k in data for k in ['evrmore_address', 'challenge', 'signature']):
                    logger.warning("Missing parameters in authenticate request")
                    return jsonify({
                        "error": "Missing required parameters (evrmore_address, challenge, signature)"
                    }), 400
                
                evrmore_address = data['evrmore_address']
                challenge = data['challenge']
                signature = data['signature']
                
                # Get client information for metrics
                ip_address = request.remote_addr
                user_agent = request.headers.get('User-Agent', 'Unknown')
                
                # Log authentication attempt with detailed metrics
                logger.info(f"Authentication attempt for {evrmore_address} from IP: {ip_address}, User-Agent: {user_agent}")
                logger.debug(f"Challenge: {challenge}")
                logger.debug(f"Signature: {signature[:10]}...")
                
                # Authenticate
                try:
                    result = self.auth.authenticate(
                        evrmore_address=evrmore_address,
                        challenge=challenge,
                        signature=signature
                    )
                    
                    # Format expiration time
                    if result.get('expires_at'):
                        result['expires_at'] = result['expires_at'].isoformat()
                    
                    # Log successful authentication
                    user_id = result.get('user', {}).get('id', 'unknown')
                    logger.info(f"Authentication successful for user {user_id} (address: {evrmore_address})")
                    
                    # Record login metrics
                    self._record_login_metrics(user_id, ip_address, user_agent, True)
                    
                    return jsonify(result)
                except AuthenticationError as e:
                    logger.warning(f"Authentication failed for {evrmore_address}: {str(e)}")
                    
                    # Record failed login attempt
                    self._record_login_metrics(None, ip_address, user_agent, False, error=str(e))
                    
                    return jsonify({
                        "error": str(e)
                    }), 401
            except Exception as e:
                logger.error(f"Error in authenticate endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Token validation endpoint
        @self.app.route('/api/validate', methods=['GET'])
        def validate():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in validate request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                result = self.auth.validate_token(token)
                
                # Format expiration time
                if result.get('expires_at'):
                    result['expires_at'] = result['expires_at'].isoformat()
                
                if not result.get('valid', False):
                    return jsonify(result), 401
                
                return jsonify(result)
            except Exception as e:
                logger.error(f"Error in validate endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Logout endpoint
        @self.app.route('/api/logout', methods=['POST'])
        def logout():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in logout request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                self.auth.invalidate_token(token)
                return jsonify({
                    "success": True,
                    "message": "Successfully logged out"
                })
            except Exception as e:
                logger.error(f"Error in logout endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # User info endpoint
        @self.app.route('/api/user', methods=['GET'])
        def user():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in user request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                # Validate token first
                valid = self.auth.validate_token(token)
                if not valid.get('valid', False):
                    return jsonify({
                        "error": "Invalid token"
                    }), 401
                
                # Get user info
                user_info = self.auth.get_user_by_token(token)
                return jsonify(user_info)
            except Exception as e:
                logger.error(f"Error in user endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Update user profile endpoint
        @self.app.route('/api/user', methods=['PUT'])
        def update_user():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in update user request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                # Validate token first
                valid = self.auth.validate_token(token)
                if not valid.get('valid', False):
                    return jsonify({
                        "error": "Invalid token"
                    }), 401
                
                # Get user info and update it
                data = request.json
                if not data:
                    return jsonify({
                        "error": "No data provided"
                    }), 400
                
                user_info = self.auth.get_user_by_token(token)
                user_id = user_info.get('id')
                
                # Track changes for logging
                changes = []
                
                # Update username if provided
                if 'username' in data and data['username'] != user_info.get('username'):
                    old_username = user_info.get('username') or 'unset'
                    new_username = data['username']
                    changes.append(f"Username changed from '{old_username}' to '{new_username}'")
                    user_info['username'] = new_username
                
                # Update email if provided
                if 'email' in data and data['email'] != user_info.get('email'):
                    old_email = user_info.get('email') or 'unset'
                    new_email = data['email']
                    changes.append(f"Email changed from '{old_email}' to '{new_email}'")
                    user_info['email'] = new_email
                
                # Update bio if provided
                if 'bio' in data and data['bio'] != user_info.get('bio'):
                    user_info['bio'] = data['bio']
                    changes.append(f"Bio updated")
                
                # Update settings if provided
                if 'settings' in data:
                    user_info['settings'] = data['settings']
                    changes.append(f"Settings updated")
                
                # Save updated user info to database
                # This would involve actual database operations in a real implementation
                # For now, we'll just log the changes
                
                # Log all the changes
                if changes:
                    for change in changes:
                        logger.info(f"User {user_id} profile updated: {change}")
                
                return jsonify({
                    "success": True, 
                    "message": "Profile updated successfully",
                    "user": user_info
                })
            except Exception as e:
                logger.error(f"Error in update user endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Add backup address endpoint
        @self.app.route('/api/user/backup-address', methods=['POST'])
        def add_backup_address():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in add backup address request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                # Validate token first
                valid = self.auth.validate_token(token)
                if not valid.get('valid', False):
                    return jsonify({
                        "error": "Invalid token"
                    }), 401
                
                data = request.json
                if not data or 'backup_address' not in data:
                    return jsonify({
                        "error": "Backup address is required"
                    }), 400
                
                backup_address = data['backup_address']
                user_info = self.auth.get_user_by_token(token)
                user_id = user_info.get('id')
                
                # Add backup address to user info
                # This would involve actual database operations in a real implementation
                # For now, we'll just log the change
                logger.info(f"User {user_id} added backup address: {backup_address}")
                
                return jsonify({
                    "success": True,
                    "message": "Backup address added successfully"
                })
            except Exception as e:
                logger.error(f"Error in add backup address endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Debug endpoints (only available in debug mode)
        if self.debug:
            @self.app.route('/api/debug/challenges', methods=['GET'])
            def debug_challenges():
                challenges = self.auth.get_all_challenges()
                return jsonify({
                    "challenges": challenges
                })
            
            @self.app.route('/api/debug/users', methods=['GET'])
            def debug_users():
                users = self.auth.get_all_users()
                return jsonify({
                    "users": users
                })
        
        # Direct 2FA endpoints
        @self.app.route('/api/auth/2fa/totp/setup', methods=['POST'])
        def setup_totp():
            return self.auth.setup_totp()
            
        @self.app.route('/api/auth/2fa/totp/verify', methods=['POST'])
        def verify_totp():
            return self.auth.verify_totp()
            
        @self.app.route('/api/auth/2fa/totp/enable', methods=['POST'])
        def enable_totp():
            return self.auth.enable_totp()
            
        @self.app.route('/api/auth/2fa/totp/disable', methods=['POST'])
        def disable_totp():
            return self.auth.disable_totp()
            
        @self.app.route('/api/auth/2fa/totp/status', methods=['GET'])
        def totp_status():
            return self.auth.totp_status()
            
        @self.app.route('/api/auth/2fa/status', methods=['GET'])
        def twofa_status():
            return self.auth.twofa_status()
        
        # 404 handler
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                "error": "Not found"
            }), 404
    
    def run(self, host: str = '0.0.0.0', port: int = 5000, **kwargs) -> None:
        """
        Run the API server.
        
        Args:
            host: Host to bind to
            port: Port to bind to
            **kwargs: Additional arguments to pass to Flask's run method
        """
        logger.info(f"Starting Evrmore Accounts API Server on {host}:{port}")
        self.app.run(host=host, port=port, debug=self.debug, **kwargs)
        
    def get_app(self):
        """Get the Flask application.
        
        Returns:
            Flask application instance
        """
        return self.app
        
    def get_jwt_manager(self):
        """Get the JWT manager.
        
        Returns:
            JWTManager instance
        """
        return self.jwt 

    def setup_routes(self):
        """Set up the API routes."""
        # Add a health check endpoint
        @self.app.route('/health', methods=['GET', 'OPTIONS'])
        def health_check():
            """Health check endpoint to verify API availability."""
            # Add proper CORS headers for direct health endpoint
            if request.method == 'OPTIONS':
                response = self.app.make_default_options_response()
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
                response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
                return response
                
            try:
                return jsonify({
                    "status": "ok",
                    "version": __version__,
                    "service": "evrmore-accounts"
                }), 200
            except Exception as e:
                logger.error(f"Error in health check: {str(e)}")
                return jsonify({
                    "status": "error",
                    "error": str(e)
                }), 500
        
        # Also add a health endpoint at /api/health for consistency
        @self.app.route('/api/health', methods=['GET', 'OPTIONS'])
        def api_health_check():
            """Health check endpoint to verify API availability (with /api prefix)."""
            # Add proper CORS headers for API health endpoint
            if request.method == 'OPTIONS':
                response = self.app.make_default_options_response()
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
                response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
                return response
                
            try:
                return jsonify({
                    "status": "ok",
                    "version": __version__,
                    "service": "evrmore-accounts"
                }), 200
            except Exception as e:
                logger.error(f"Error in API health check: {str(e)}")
                return jsonify({
                    "status": "error",
                    "error": str(e)
                }), 500
        
        logger.info("Health check endpoints registered at /health and /api/health")
        
        # Register API routes
        self._register_routes()
        
        logger.info("Evrmore Accounts API Server initialized")
    
    def _register_routes(self) -> None:
        """Register API routes with Flask."""
        
        # Challenge generation endpoint
        @self.app.route('/api/challenge', methods=['POST'])
        def challenge():
            try:
                data = request.json
                if not data or 'evrmore_address' not in data:
                    logger.warning("Missing evrmore_address in challenge request")
                    return jsonify({
                        "error": "Missing evrmore_address parameter"
                    }), 400
                
                evrmore_address = data['evrmore_address']
                expire_minutes = int(data.get('expire_minutes', 10))
                
                # Generate challenge
                result = self.auth.generate_challenge(
                    evrmore_address=evrmore_address,
                    expire_minutes=expire_minutes
                )
                
                # Format expiration time
                if result.get('expires_at'):
                    result['expires_at'] = result['expires_at'].isoformat()
                
                return jsonify(result)
            except Exception as e:
                logger.error(f"Error in challenge endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Authentication endpoint
        @self.app.route('/api/authenticate', methods=['POST'])
        def authenticate():
            try:
                data = request.json
                if not data or not all(k in data for k in ['evrmore_address', 'challenge', 'signature']):
                    logger.warning("Missing parameters in authenticate request")
                    return jsonify({
                        "error": "Missing required parameters (evrmore_address, challenge, signature)"
                    }), 400
                
                evrmore_address = data['evrmore_address']
                challenge = data['challenge']
                signature = data['signature']
                
                # Get client information for metrics
                ip_address = request.remote_addr
                user_agent = request.headers.get('User-Agent', 'Unknown')
                
                # Log authentication attempt with detailed metrics
                logger.info(f"Authentication attempt for {evrmore_address} from IP: {ip_address}, User-Agent: {user_agent}")
                logger.debug(f"Challenge: {challenge}")
                logger.debug(f"Signature: {signature[:10]}...")
                
                # Authenticate
                try:
                    result = self.auth.authenticate(
                        evrmore_address=evrmore_address,
                        challenge=challenge,
                        signature=signature
                    )
                    
                    # Format expiration time
                    if result.get('expires_at'):
                        result['expires_at'] = result['expires_at'].isoformat()
                    
                    # Log successful authentication
                    user_id = result.get('user', {}).get('id', 'unknown')
                    logger.info(f"Authentication successful for user {user_id} (address: {evrmore_address})")
                    
                    # Record login metrics
                    self._record_login_metrics(user_id, ip_address, user_agent, True)
                    
                    return jsonify(result)
                except AuthenticationError as e:
                    logger.warning(f"Authentication failed for {evrmore_address}: {str(e)}")
                    
                    # Record failed login attempt
                    self._record_login_metrics(None, ip_address, user_agent, False, error=str(e))
                    
                    return jsonify({
                        "error": str(e)
                    }), 401
            except Exception as e:
                logger.error(f"Error in authenticate endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Token validation endpoint
        @self.app.route('/api/validate', methods=['GET'])
        def validate():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in validate request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                result = self.auth.validate_token(token)
                
                # Format expiration time
                if result.get('expires_at'):
                    result['expires_at'] = result['expires_at'].isoformat()
                
                if not result.get('valid', False):
                    return jsonify(result), 401
                
                return jsonify(result)
            except Exception as e:
                logger.error(f"Error in validate endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Logout endpoint
        @self.app.route('/api/logout', methods=['POST'])
        def logout():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in logout request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                self.auth.invalidate_token(token)
                return jsonify({
                    "success": True,
                    "message": "Successfully logged out"
                })
            except Exception as e:
                logger.error(f"Error in logout endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # User info endpoint
        @self.app.route('/api/user', methods=['GET'])
        def user():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in user request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                # Validate token first
                valid = self.auth.validate_token(token)
                if not valid.get('valid', False):
                    return jsonify({
                        "error": "Invalid token"
                    }), 401
                
                # Get user info
                user_info = self.auth.get_user_by_token(token)
                return jsonify(user_info)
            except Exception as e:
                logger.error(f"Error in user endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Update user profile endpoint
        @self.app.route('/api/user', methods=['PUT'])
        def update_user():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in update user request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                # Validate token first
                valid = self.auth.validate_token(token)
                if not valid.get('valid', False):
                    return jsonify({
                        "error": "Invalid token"
                    }), 401
                
                # Get user info and update it
                data = request.json
                if not data:
                    return jsonify({
                        "error": "No data provided"
                    }), 400
                
                user_info = self.auth.get_user_by_token(token)
                user_id = user_info.get('id')
                
                # Track changes for logging
                changes = []
                
                # Update username if provided
                if 'username' in data and data['username'] != user_info.get('username'):
                    old_username = user_info.get('username') or 'unset'
                    new_username = data['username']
                    changes.append(f"Username changed from '{old_username}' to '{new_username}'")
                    user_info['username'] = new_username
                
                # Update email if provided
                if 'email' in data and data['email'] != user_info.get('email'):
                    old_email = user_info.get('email') or 'unset'
                    new_email = data['email']
                    changes.append(f"Email changed from '{old_email}' to '{new_email}'")
                    user_info['email'] = new_email
                
                # Update bio if provided
                if 'bio' in data and data['bio'] != user_info.get('bio'):
                    user_info['bio'] = data['bio']
                    changes.append(f"Bio updated")
                
                # Update settings if provided
                if 'settings' in data:
                    user_info['settings'] = data['settings']
                    changes.append(f"Settings updated")
                
                # Save updated user info to database
                # This would involve actual database operations in a real implementation
                # For now, we'll just log the changes
                
                # Log all the changes
                if changes:
                    for change in changes:
                        logger.info(f"User {user_id} profile updated: {change}")
                
                return jsonify({
                    "success": True, 
                    "message": "Profile updated successfully",
                    "user": user_info
                })
            except Exception as e:
                logger.error(f"Error in update user endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Add backup address endpoint
        @self.app.route('/api/user/backup-address', methods=['POST'])
        def add_backup_address():
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning("Missing or invalid Authorization header in add backup address request")
                return jsonify({
                    "error": "Bearer token is required"
                }), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                # Validate token first
                valid = self.auth.validate_token(token)
                if not valid.get('valid', False):
                    return jsonify({
                        "error": "Invalid token"
                    }), 401
                
                data = request.json
                if not data or 'backup_address' not in data:
                    return jsonify({
                        "error": "Backup address is required"
                    }), 400
                
                backup_address = data['backup_address']
                user_info = self.auth.get_user_by_token(token)
                user_id = user_info.get('id')
                
                # Add backup address to user info
                # This would involve actual database operations in a real implementation
                # For now, we'll just log the change
                logger.info(f"User {user_id} added backup address: {backup_address}")
                
                return jsonify({
                    "success": True,
                    "message": "Backup address added successfully"
                })
            except Exception as e:
                logger.error(f"Error in add backup address endpoint: {str(e)}", exc_info=self.debug)
                return jsonify({
                    "error": str(e)
                }), 500
        
        # Debug endpoints (only available in debug mode)
        if self.debug:
            @self.app.route('/api/debug/challenges', methods=['GET'])
            def debug_challenges():
                challenges = self.auth.get_all_challenges()
                return jsonify({
                    "challenges": challenges
                })
            
            @self.app.route('/api/debug/users', methods=['GET'])
            def debug_users():
                users = self.auth.get_all_users()
                return jsonify({
                    "users": users
                })
        
        # Direct 2FA endpoints
        @self.app.route('/api/auth/2fa/totp/setup', methods=['POST'])
        def setup_totp():
            return self.auth.setup_totp()
            
        @self.app.route('/api/auth/2fa/totp/verify', methods=['POST'])
        def verify_totp():
            return self.auth.verify_totp()
            
        @self.app.route('/api/auth/2fa/totp/enable', methods=['POST'])
        def enable_totp():
            return self.auth.enable_totp()
            
        @self.app.route('/api/auth/2fa/totp/disable', methods=['POST'])
        def disable_totp():
            return self.auth.disable_totp()
            
        @self.app.route('/api/auth/2fa/totp/status', methods=['GET'])
        def totp_status():
            return self.auth.totp_status()
            
        @self.app.route('/api/auth/2fa/status', methods=['GET'])
        def twofa_status():
            return self.auth.twofa_status()
        
        # 404 handler
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                "error": "Not found"
            }), 404
        
        logger.info("Evrmore Accounts API Server initialized") 