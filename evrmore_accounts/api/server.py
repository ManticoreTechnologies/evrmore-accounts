#!/usr/bin/env python3
"""
Evrmore Accounts API Server

This module provides a Flask-based API server for the Evrmore Accounts service.
"""
import os
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from evrmore_authentication.exceptions import AuthenticationError

from .auth import AccountsAuth

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
        
        # Initialize auth module
        self.auth = AccountsAuth(debug=debug)
        
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
                
                # Log authentication attempt
                logger.info(f"Authentication attempt for {evrmore_address}")
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
                    
                    return jsonify(result)
                except AuthenticationError as e:
                    logger.warning(f"Authentication failed: {str(e)}")
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
        
        # Health check endpoint
        @self.app.route('/api/health', methods=['GET'])
        def health():
            return jsonify({
                "status": "ok",
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0.0"
            })
        
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
        
    def get_app(self) -> Flask:
        """
        Get the Flask application.
        
        Returns:
            Flask application
        """
        return self.app 