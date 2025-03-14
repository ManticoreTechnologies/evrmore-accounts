#!/usr/bin/env python3
"""
Evrmore Accounts Configuration

This module manages configuration settings for the Evrmore Accounts API.
It loads settings from environment variables with sensible defaults.
"""
import os
from typing import Dict, Any

class Config:
    """Base configuration class"""
    # Flask settings
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-in-production")
    
    # JWT settings
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt-secret-change-in-production")
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    JWT_ALGORITHM = "HS256"
    
    # Rate limiting settings
    RATE_LIMIT_GLOBAL = int(os.environ.get("RATE_LIMIT_GLOBAL", "100"))
    RATE_LIMIT_AUTH = int(os.environ.get("RATE_LIMIT_AUTH", "5"))
    RATE_LIMIT_CHALLENGE = int(os.environ.get("RATE_LIMIT_CHALLENGE", "10"))
    RATE_LIMIT_USER = int(os.environ.get("RATE_LIMIT_USER", "30"))
    
    # Server settings
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "5000"))
    
    # Database settings
    DATABASE_URI = os.environ.get("DATABASE_URI", "sqlite:///instance/evrmore_accounts.db")
    
    # Evrmore settings
    EVRMORE_RPC_URL = os.environ.get("EVRMORE_RPC_URL", "http://localhost:8819")
    EVRMORE_RPC_USER = os.environ.get("EVRMORE_RPC_USER", "user")
    EVRMORE_RPC_PASSWORD = os.environ.get("EVRMORE_RPC_PASSWORD", "password")

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Stricter rate limits for testing
    RATE_LIMIT_GLOBAL = 10
    RATE_LIMIT_AUTH = 5
    RATE_LIMIT_CHALLENGE = 5
    RATE_LIMIT_USER = 10
    
    # Use in-memory database for testing
    DATABASE_URI = "sqlite:///:memory:"

class ProductionConfig(Config):
    """Production configuration"""
    # Production should use environment variables for all sensitive settings
    
    def __init__(self):
        # Ensure required settings are provided in production
        required_settings = [
            "SECRET_KEY",
            "JWT_SECRET_KEY"
        ]
        
        missing = [s for s in required_settings if not os.environ.get(s)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

# Configuration mapping
config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig
}

def get_config() -> Dict[str, Any]:
    """Get configuration based on environment
    
    Returns:
        Configuration dictionary
    """
    env = os.environ.get("FLASK_ENV", "development")
    config_class = config_by_name.get(env, DevelopmentConfig)
    
    if env == "production":
        config = ProductionConfig()
    else:
        config = config_class()
    
    return {k: v for k, v in config.__dict__.items() if not k.startswith('_')} 