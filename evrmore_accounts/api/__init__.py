"""
Evrmore Accounts API

This package provides the API components for Evrmore Accounts, 
including authentication and account management functionality.
"""

# Import blueprints for Flask application
from .auth import auth_blueprint
from .user import user_blueprint
from .health import health_blueprint
from .twofa import twofa_blueprint

__all__ = ['auth_blueprint', 'user_blueprint', 'health_blueprint', 'twofa_blueprint'] 