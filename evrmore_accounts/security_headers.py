#!/usr/bin/env python3
"""
Security Headers Middleware for Evrmore Accounts

This module provides a Flask middleware to add security headers to all API responses.
"""
from typing import Dict, Optional, Callable, Any
from flask import Flask, Response

class SecurityHeadersMiddleware:
    """Middleware to add security headers to all responses"""
    
    def __init__(self, app: Optional[Flask] = None):
        """Initialize the middleware
        
        Args:
            app: Flask application instance
        """
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
        """Initialize with a Flask application
        
        Args:
            app: Flask application instance
        """
        app.after_request(self.add_security_headers)
    
    def add_security_headers(self, response: Response) -> Response:
        """Add security headers to response
        
        Args:
            response: Flask response object
            
        Returns:
            Response object with security headers
        """
        for header, value in self.headers.items():
            response.headers.setdefault(header, value)
        
        return response

def init_security_headers(app: Flask) -> None:
    """Initialize security headers middleware
    
    Args:
        app: Flask application instance
    """
    SecurityHeadersMiddleware(app)
    app.logger.info("Security headers middleware initialized")

# Example usage:
# from security_headers import init_security_headers
# 
# app = Flask(__name__)
# init_security_headers(app) 