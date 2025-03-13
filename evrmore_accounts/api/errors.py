#!/usr/bin/env python3
"""
Evrmore Accounts API Error Handlers

This module provides standardized error responses for the API.
It ensures consistent error formatting and appropriate HTTP status codes.
"""
import logging
import traceback
import json
from typing import Dict, Any, Optional, Tuple, List, Union

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

# Configure logging
logger = logging.getLogger("evrmore_accounts.errors")

# Map of custom error codes to HTTP status codes and messages
ERROR_CODES = {
    # Authentication errors (400-499)
    "invalid_input": (400, "Invalid request parameters"),
    "authentication_required": (401, "Authentication is required"),
    "invalid_token": (401, "Invalid or expired token"),
    "invalid_signature": (401, "Invalid signature"),
    "invalid_challenge": (401, "Invalid or expired challenge"),
    "token_expired": (401, "Token has expired"),
    "access_denied": (403, "You do not have permission to access this resource"),
    "not_found": (404, "The requested resource was not found"),
    "method_not_allowed": (405, "Method not allowed for this endpoint"),
    "rate_limit_exceeded": (429, "Rate limit exceeded, please try again later"),
    
    # Two-factor errors (420-424)
    "2fa_required": (403, "Two-factor authentication is required"),
    "2fa_already_enabled": (400, "Two-factor authentication is already enabled"),
    "2fa_not_enabled": (400, "Two-factor authentication is not enabled"),
    "2fa_invalid_code": (400, "Invalid two-factor authentication code"),
    
    # Server errors (500-599)
    "server_error": (500, "An internal server error occurred"),
    "not_implemented": (501, "This feature is not yet implemented"),
    "service_unavailable": (503, "Service temporarily unavailable"),
    "database_error": (500, "Database operation failed"),
    
    # Validation errors (460-469)
    "validation_error": (400, "Request validation failed"),
    "missing_parameter": (400, "Required parameter is missing"),
    "invalid_parameter": (400, "Parameter has invalid value"),
    
    # Resource errors (470-479)
    "resource_exists": (409, "Resource already exists"),
    "resource_in_use": (409, "Resource is in use"),
    "resource_locked": (423, "Resource is locked"),
    
    # Business logic errors (480-489)
    "business_rule_violation": (400, "Business rule violated")
}

class APIError(Exception):
    """Custom exception for API errors with error code and details"""
    
    def __init__(self, error_code: str, message: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        """Initialize API error
        
        Args:
            error_code: The error code from ERROR_CODES
            message: Optional custom message (defaults to standard message for the error code)
            details: Optional details about the error for debugging/display
        """
        self.error_code = error_code
        status_code, default_message = ERROR_CODES.get(error_code, (500, "Unknown error"))
        self.status_code = status_code
        self.message = message or default_message
        self.details = details or {}
        super().__init__(self.message)

def format_error_response(error_code: str, message: str, status_code: int, details: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], int]:
    """Format a standardized error response
    
    Args:
        error_code: The error code
        message: The error message
        status_code: The HTTP status code
        details: Optional details about the error
        
    Returns:
        Tuple of response JSON and status code
    """
    response = {
        "success": False,
        "error": {
            "code": error_code,
            "message": message
        }
    }
    
    if details:
        response["error"]["details"] = details
    
    return jsonify(response), status_code

def init_error_handlers(app: Flask) -> None:
    """Initialize error handlers for a Flask application
    
    Args:
        app: The Flask application
    """
    @app.errorhandler(APIError)
    def handle_api_error(error):
        """Handle custom APIError exceptions"""
        logger.warning(f"API Error: {error.error_code} - {error.message}")
        
        # Log details if present and use appropriate log level based on status code
        if error.details:
            if error.status_code >= 500:
                logger.error(f"Error details: {json.dumps(error.details)}")
            else:
                logger.info(f"Error details: {json.dumps(error.details)}")
        
        return format_error_response(error.error_code, error.message, error.status_code, error.details)
    
    @app.errorhandler(400)
    def handle_bad_request(error):
        """Handle 400 Bad Request errors"""
        logger.warning(f"Bad Request: {request.path} - {str(error)}")
        return format_error_response("invalid_input", str(error), 400)
    
    @app.errorhandler(401)
    def handle_unauthorized(error):
        """Handle 401 Unauthorized errors"""
        logger.warning(f"Unauthorized: {request.path} - {str(error)}")
        return format_error_response("authentication_required", str(error) or "Authentication required", 401)
    
    @app.errorhandler(403)
    def handle_forbidden(error):
        """Handle 403 Forbidden errors"""
        logger.warning(f"Forbidden: {request.path} - {str(error)}")
        return format_error_response("access_denied", str(error) or "Access denied", 403)
    
    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 Not Found errors"""
        logger.info(f"Not Found: {request.path}")
        return format_error_response("not_found", str(error) or "Resource not found", 404)
    
    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        """Handle 405 Method Not Allowed errors"""
        logger.info(f"Method Not Allowed: {request.method} {request.path}")
        return format_error_response(
            "method_not_allowed", 
            f"Method {request.method} not allowed for this endpoint", 
            405
        )
    
    @app.errorhandler(429)
    def handle_rate_limit_exceeded(error):
        """Handle 429 Too Many Requests errors"""
        logger.warning(f"Rate Limit Exceeded: {request.path} - IP: {request.remote_addr}")
        return format_error_response("rate_limit_exceeded", str(error) or "Rate limit exceeded", 429)
    
    @app.errorhandler(500)
    def handle_server_error(error):
        """Handle 500 Internal Server Error errors"""
        logger.error(f"Server Error: {request.path} - {str(error)}")
        logger.error(traceback.format_exc())
        return format_error_response("server_error", "An internal server error occurred", 500)
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        """Handle other HTTP exceptions"""
        logger.warning(f"HTTP Exception: {error.code} - {request.path} - {error.description}")
        
        error_code = "server_error" if error.code >= 500 else "client_error"
        return format_error_response(error_code, error.description, error.code)
    
    @app.errorhandler(Exception)
    def handle_generic_exception(error):
        """Handle generic exceptions"""
        logger.error(f"Unhandled Exception: {request.path} - {str(error)}")
        logger.error(traceback.format_exc())
        return format_error_response("server_error", "An unexpected error occurred", 500)

# Validation error helpers

def validation_error(message: str, field: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> APIError:
    """Create a validation error
    
    Args:
        message: Error message
        field: The field that failed validation
        details: Additional error details
        
    Returns:
        APIError instance
    """
    error_details = details or {}
    if field:
        error_details["field"] = field
    
    return APIError("validation_error", message, error_details)

def missing_parameter(param_name: str) -> APIError:
    """Create a missing parameter error
    
    Args:
        param_name: The name of the missing parameter
        
    Returns:
        APIError instance
    """
    return APIError(
        "missing_parameter", 
        f"Required parameter '{param_name}' is missing", 
        {"parameter": param_name}
    )

def invalid_parameter(param_name: str, reason: str = "invalid value") -> APIError:
    """Create an invalid parameter error
    
    Args:
        param_name: The name of the invalid parameter
        reason: The reason the parameter is invalid
        
    Returns:
        APIError instance
    """
    return APIError(
        "invalid_parameter", 
        f"Parameter '{param_name}' has an invalid value: {reason}", 
        {"parameter": param_name, "reason": reason}
    )

def validate_required_fields(data: Dict[str, Any], required_fields: List[str]) -> None:
    """Validate that required fields are present in the data
    
    Args:
        data: The data to validate
        required_fields: List of required field names
        
    Raises:
        APIError: If a required field is missing
    """
    for field in required_fields:
        if field not in data or data[field] is None:
            raise missing_parameter(field)

# Authentication error helpers

def authentication_required() -> APIError:
    """Create an authentication required error
    
    Returns:
        APIError instance
    """
    return APIError("authentication_required", "Authentication is required to access this resource")

def invalid_token(reason: str = "invalid or expired") -> APIError:
    """Create an invalid token error
    
    Args:
        reason: The reason the token is invalid
        
    Returns:
        APIError instance
    """
    return APIError("invalid_token", f"Token is {reason}", {"reason": reason})

def access_denied(reason: str = "insufficient permissions") -> APIError:
    """Create an access denied error
    
    Args:
        reason: The reason access is denied
        
    Returns:
        APIError instance
    """
    return APIError("access_denied", f"Access denied: {reason}", {"reason": reason}) 