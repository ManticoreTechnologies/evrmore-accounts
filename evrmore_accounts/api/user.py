#!/usr/bin/env python3
"""
Evrmore Accounts User API

This module provides endpoints for managing user profiles.
"""
import logging
from flask import Blueprint, request, jsonify, g, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from evrmore_accounts.database import get_db, User

# Configure logging
logger = logging.getLogger("evrmore_accounts.user")

# Create blueprint
user_blueprint = Blueprint('user', __name__)

@user_blueprint.route('/user', methods=['GET'])
@jwt_required()
def get_user_profile():
    """Get the authenticated user's profile
    
    Returns:
        User profile information
    """
    user_id = get_jwt_identity()
    
    # Get database session
    db = get_db()
    
    # Get user from database
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        return jsonify({
            "success": False,
            "error": {
                "code": "user_not_found",
                "message": "User not found"
            }
        }), 404
    
    # Return user profile
    return jsonify({
        "success": True,
        "user": user.to_dict()
    })

@user_blueprint.route('/user', methods=['PUT'])
@jwt_required()
def update_user_profile():
    """Update the authenticated user's profile
    
    Request body:
        username: (optional) New username
        email: (optional) New email address
        avatar: (optional) New avatar URL
        bio: (optional) New bio text
        
    Returns:
        Updated user profile
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data:
        return jsonify({
            "success": False,
            "error": {
                "code": "invalid_request",
                "message": "Invalid request data"
            }
        }), 400
    
    # Get database session
    db = get_db()
    
    # Get user from database
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        return jsonify({
            "success": False,
            "error": {
                "code": "user_not_found",
                "message": "User not found"
            }
        }), 404
    
    # Update user profile fields
    if 'username' in data:
        user.username = data['username']
    
    if 'email' in data:
        user.email = data['email']
    
    if 'avatar' in data:
        user.avatar = data['avatar']
    
    if 'bio' in data:
        user.bio = data['bio']
    
    # Update settings if provided
    if 'settings' in data and isinstance(data['settings'], dict):
        # Merge with existing settings
        current_settings = user.settings_dict
        current_settings.update(data['settings'])
        user.settings_dict = current_settings
    
    # Save changes
    db.commit()
    
    # Log the update
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_security_event(
                "profile_updated",
                user_id,
                {"fields": list(data.keys())}
            )
    
    # Return updated user profile
    return jsonify({
        "success": True,
        "user": user.to_dict()
    })

@user_blueprint.route('/user/backup-address', methods=['POST'])
@jwt_required()
def add_backup_address():
    """Add a backup Evrmore address to the user's account
    
    Request body:
        evrmore_address: Backup Evrmore address
        signature: Signature proving ownership of the address
        
    Returns:
        Success message
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    
    # Validate required parameters
    required_fields = ['evrmore_address', 'signature']
    for field in required_fields:
        if field not in data:
            return jsonify({
                "success": False,
                "error": {
                    "code": "missing_parameter",
                    "message": f"Missing required parameter: {field}"
                }
            }), 400
    
    # Get database session
    db = get_db()
    
    # Get user from database
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        return jsonify({
            "success": False,
            "error": {
                "code": "user_not_found",
                "message": "User not found"
            }
        }), 404
    
    # Verify the signature (this would call the same verification function as in auth.py)
    from evrmore_accounts.api.auth import verify_evrmore_signature
    
    # Generate a message to sign
    message = f"Add this address as a backup for Evrmore account: {user.evrmore_address}"
    
    # Verify the signature
    if not verify_evrmore_signature(data['evrmore_address'], message, data['signature']):
        return jsonify({
            "success": False,
            "error": {
                "code": "invalid_signature",
                "message": "Invalid signature"
            }
        }), 401
    
    # Store the backup address in user settings
    settings = user.settings_dict
    
    # Initialize backup_addresses if it doesn't exist
    if 'backup_addresses' not in settings:
        settings['backup_addresses'] = []
    
    # Check if address already exists
    if data['evrmore_address'] in settings['backup_addresses']:
        return jsonify({
            "success": False,
            "error": {
                "code": "address_exists",
                "message": "This address is already registered as a backup"
            }
        }), 400
    
    # Add the new backup address
    settings['backup_addresses'].append(data['evrmore_address'])
    user.settings_dict = settings
    
    # Save changes
    db.commit()
    
    # Log the addition
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_security_event(
                "backup_address_added",
                user_id,
                {"address": data['evrmore_address']}
            )
    
    return jsonify({
        "success": True,
        "message": "Backup address added successfully",
        "backup_addresses": settings['backup_addresses']
    })

@user_blueprint.route('/user/backup-address/<address>', methods=['DELETE'])
@jwt_required()
def remove_backup_address(address):
    """Remove a backup Evrmore address from the user's account
    
    Args:
        address: Evrmore address to remove
        
    Returns:
        Success message
    """
    user_id = get_jwt_identity()
    
    # Get database session
    db = get_db()
    
    # Get user from database
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        return jsonify({
            "success": False,
            "error": {
                "code": "user_not_found",
                "message": "User not found"
            }
        }), 404
    
    # Get user settings
    settings = user.settings_dict
    
    # Check if backup_addresses exists
    if 'backup_addresses' not in settings or not settings['backup_addresses']:
        return jsonify({
            "success": False,
            "error": {
                "code": "no_backup_addresses",
                "message": "No backup addresses registered"
            }
        }), 404
    
    # Check if address exists in backup addresses
    if address not in settings['backup_addresses']:
        return jsonify({
            "success": False,
            "error": {
                "code": "address_not_found",
                "message": "Address not found in backup addresses"
            }
        }), 404
    
    # Remove the address
    settings['backup_addresses'].remove(address)
    user.settings_dict = settings
    
    # Save changes
    db.commit()
    
    # Log the removal
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_security_event(
                "backup_address_removed",
                user_id,
                {"address": address}
            )
    
    return jsonify({
        "success": True,
        "message": "Backup address removed successfully",
        "backup_addresses": settings['backup_addresses']
    }) 