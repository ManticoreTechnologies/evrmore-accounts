#!/usr/bin/env python3
"""
Evrmore Accounts Two-Factor Authentication (2FA) API

This module provides endpoints for managing two-factor authentication.
"""
import os
import logging
import secrets
import pyotp
from typing import Dict, List, Any, Optional

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from evrmore_accounts.database import get_db, User, TOTPSecret, RecoveryCode

# Configure logging
logger = logging.getLogger("evrmore_accounts.twofa")

# Create blueprint
twofa_blueprint = Blueprint('twofa', __name__)

# Number of recovery codes to generate
RECOVERY_CODE_COUNT = 10
# Length of each recovery code
RECOVERY_CODE_LENGTH = 8

def generate_recovery_codes(user_id: str, count: int = RECOVERY_CODE_COUNT) -> List[str]:
    """Generate recovery codes for a user.
    
    Args:
        user_id: User ID
        count: Number of codes to generate
        
    Returns:
        List of recovery codes
    """
    db = get_db()
    
    # Delete existing unused recovery codes
    db.query(RecoveryCode).filter_by(user_id=user_id, used=False).delete()
    
    # Generate new codes
    codes = []
    for _ in range(count):
        # Generate a random code
        code = secrets.token_hex(RECOVERY_CODE_LENGTH // 2)
        
        # Create a new recovery code record
        recovery_code = RecoveryCode(
            user_id=user_id,
            code=code
        )
        db.add(recovery_code)
        codes.append(code)
    
    # Commit the changes
    db.commit()
    
    return codes

@twofa_blueprint.route('/totp/setup', methods=['POST'])
@jwt_required()
def setup_totp():
    """Set up TOTP authentication for the user.
    
    Returns:
        TOTP setup information
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
    
    # Check if TOTP is already enabled
    totp_secret = db.query(TOTPSecret).filter_by(user_id=user_id).first()
    
    if totp_secret and totp_secret.enabled:
        return jsonify({
            "success": False,
            "error": {
                "code": "totp_already_enabled",
                "message": "TOTP is already enabled for this user"
            }
        }), 400
    
    # Generate a new TOTP secret if one doesn't exist or create a new one
    secret = None
    if totp_secret:
        secret = totp_secret.secret
    else:
        # Generate a new secret
        secret = pyotp.random_base32()
        
        # Create a new TOTP secret record
        totp_secret = TOTPSecret(
            user_id=user_id,
            secret=secret,
            enabled=False
        )
        db.add(totp_secret)
        db.commit()
    
    # Create a TOTP provisioning URI
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.username or user.evrmore_address,
        issuer_name="Evrmore Accounts"
    )
    
    # Log the setup
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_2fa_event(
                "totp_setup",
                user_id,
                success=True,
                method="totp"
            )
    
    return jsonify({
        "success": True,
                "secret": secret,
        "provisioning_uri": provisioning_uri
    })

@twofa_blueprint.route('/totp/verify', methods=['POST'])
@jwt_required()
def verify_totp():
    """Verify a TOTP code.
    
    Request body:
        code: TOTP code to verify
            
        Returns:
        Verification result
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'code' not in data:
        return jsonify({
            "success": False,
            "error": {
                "code": "missing_parameter",
                "message": "Missing required parameter: code"
            }
        }), 400
    
    code = data['code']
    
    # Get database session
    db = get_db()
    
    # Get TOTP secret from database
    totp_secret = db.query(TOTPSecret).filter_by(user_id=user_id).first()
    
    if not totp_secret:
        return jsonify({
            "success": False,
            "error": {
                "code": "totp_not_setup",
                "message": "TOTP is not set up for this user"
            }
        }), 400
    
    # Verify the code
    totp = pyotp.TOTP(totp_secret.secret)
    valid = totp.verify(code)
    
    # Log the verification
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_2fa_event(
                "totp_verify",
                user_id,
                success=valid,
                method="totp",
                error=None if valid else "Invalid code"
            )
    
    return jsonify({
        "success": True,
        "valid": valid
    })

@twofa_blueprint.route('/totp/enable', methods=['POST'])
@jwt_required()
def enable_totp():
    """Enable TOTP authentication for the user.
    
    Request body:
        code: TOTP code to verify before enabling
            
        Returns:
        Success message and recovery codes
        """
    user_id = get_jwt_identity()
    data = request.get_json()
        
    if not data or 'code' not in data:
        return jsonify({
                "success": False,
            "error": {
                "code": "missing_parameter",
                "message": "Missing required parameter: code"
            }
        }), 400
    
    code = data['code']
    
    # Get database session
    db = get_db()
    
    # Get TOTP secret from database
    totp_secret = db.query(TOTPSecret).filter_by(user_id=user_id).first()
    
    if not totp_secret:
        return jsonify({
                    "success": False,
            "error": {
                "code": "totp_not_setup",
                "message": "TOTP is not set up for this user"
            }
        }), 400
            
            # Verify the code
    totp = pyotp.TOTP(totp_secret.secret)
    if not totp.verify(code):
        # Log the failed verification
        if hasattr(current_app, 'security'):
            security_logging = current_app.security.get("security_logging")
            if security_logging:
                security_logging.log_2fa_event(
                    "totp_enable",
                    user_id,
                    success=False,
                    method="totp",
                    error="Invalid code"
                )
        
        return jsonify({
                "success": False,
            "error": {
                "code": "invalid_code",
                "message": "Invalid TOTP code"
            }
        }), 400
    
    # Enable TOTP
    totp_secret.enabled = True
    db.commit()
    
    # Generate recovery codes
    recovery_codes = generate_recovery_codes(user_id)
    
    # Log the enablement
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_2fa_event(
                "totp_enable",
                user_id,
                success=True,
                method="totp"
            )
    
    return jsonify({
                "success": True,
        "message": "TOTP authentication enabled",
        "recovery_codes": recovery_codes
    })

@twofa_blueprint.route('/totp/disable', methods=['POST'])
@jwt_required()
def disable_totp():
    """Disable TOTP authentication for the user.
    
    Request body:
        code: TOTP code to verify before disabling
            
        Returns:
        Success message
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'code' not in data:
        return jsonify({
            "success": False,
            "error": {
                "code": "missing_parameter",
                "message": "Missing required parameter: code"
            }
        }), 400
    
    code = data['code']
    
    # Get database session
    db = get_db()
    
    # Get TOTP secret from database
    totp_secret = db.query(TOTPSecret).filter_by(user_id=user_id).first()
    
    if not totp_secret or not totp_secret.enabled:
        return jsonify({
            "success": False,
            "error": {
                "code": "totp_not_enabled",
                "message": "TOTP is not enabled for this user"
            }
        }), 400
    
    # Verify the code
    totp = pyotp.TOTP(totp_secret.secret)
    if not totp.verify(code):
        # Log the failed verification
        if hasattr(current_app, 'security'):
            security_logging = current_app.security.get("security_logging")
            if security_logging:
                security_logging.log_2fa_event(
                    "totp_disable",
                    user_id,
                    success=False,
                    method="totp",
                    error="Invalid code"
                )
        
        return jsonify({
            "success": False,
            "error": {
                "code": "invalid_code",
                "message": "Invalid TOTP code"
            }
        }), 400
    
    # Disable TOTP
    totp_secret.enabled = False
    db.commit()
    
    # Log the disablement
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_2fa_event(
                "totp_disable",
                user_id,
                success=True,
                method="totp"
            )
    
    return jsonify({
        "success": True,
        "message": "TOTP authentication disabled"
    })

@twofa_blueprint.route('/totp/status', methods=['GET'])
@jwt_required()
def totp_status():
    """Get TOTP status for the user.
    
    Returns:
        TOTP status information
    """
    user_id = get_jwt_identity()
    
    # Get database session
    db = get_db()
    
    # Get TOTP secret from database
    totp_secret = db.query(TOTPSecret).filter_by(user_id=user_id).first()
    
    status = {
        "enabled": False,
        "setup": False
    }
    
    if totp_secret:
        status["setup"] = True
        status["enabled"] = totp_secret.enabled
    
    return jsonify({
        "success": True,
        "totp": status
    })

@twofa_blueprint.route('/status', methods=['GET'])
@jwt_required()
def twofa_status():
    """Get overall 2FA status for the user.
            
        Returns:
        Overall 2FA status information
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
    
    # Get TOTP status
    totp_secret = db.query(TOTPSecret).filter_by(user_id=user_id).first()
    totp_status = {
        "enabled": False,
        "setup": False
    }
    
    if totp_secret:
        totp_status["setup"] = True
        totp_status["enabled"] = totp_secret.enabled
    
    # Get WebAuthn status (simplified for now)
    webauthn_status = {
        "enabled": False,
        "credentials": []
    }
    
    # Get recovery codes status
    recovery_codes_count = db.query(RecoveryCode).filter_by(user_id=user_id, used=False).count()
    
    return jsonify({
        "success": True,
        "enabled": user.two_fa_enabled,
        "totp": totp_status,
        "webauthn": webauthn_status,
        "recovery_codes": {
            "count": recovery_codes_count
        }
    })

@twofa_blueprint.route('/recovery-codes', methods=['GET'])
@jwt_required()
def get_recovery_codes():
    """Get recovery codes for the user.
            
        Returns:
        List of unused recovery codes
    """
    user_id = get_jwt_identity()
    
    # Get database session
    db = get_db()
    
    # Check if 2FA is enabled
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        return jsonify({
                    "success": False,
            "error": {
                "code": "user_not_found",
                "message": "User not found"
            }
        }), 404
    
    if not user.two_fa_enabled:
        return jsonify({
                "success": False,
            "error": {
                "code": "2fa_not_enabled",
                "message": "Two-factor authentication is not enabled for this user"
            }
        }), 400
    
    # Get unused recovery codes
    recovery_codes = db.query(RecoveryCode).filter_by(user_id=user_id, used=False).all()
    codes = [code.code for code in recovery_codes]
    
    # If no recovery codes exist, generate new ones
    if not codes:
        codes = generate_recovery_codes(user_id)
    
    # Log the retrieval
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_2fa_event(
                "recovery_codes_get",
                user_id,
                success=True,
                method="recovery"
            )
    
    return jsonify({
        "success": True,
        "recovery_codes": codes
    })

@twofa_blueprint.route('/recovery-codes/verify', methods=['POST'])
def verify_recovery_code():
    """Verify a recovery code.
    
    Request body:
        code: Recovery code to verify
        user_id: User ID (required when not authenticated)
            
        Returns:
        Verification result
    """
    data = request.get_json()
    
    if not data or 'code' not in data:
        return jsonify({
            "success": False,
            "error": {
                "code": "missing_parameter",
                "message": "Missing required parameter: code"
            }
        }), 400
    
    code = data['code']
    
    # Check if user is authenticated
    user_id = None
    try:
        user_id = get_jwt_identity()
    except:
        # Not authenticated, get user_id from request
        if 'user_id' not in data:
            return jsonify({
                "success": False,
                "error": {
                    "code": "missing_parameter",
                    "message": "Missing required parameter: user_id"
                }
            }), 400
        
        user_id = data['user_id']
    
    # Get database session
    db = get_db()
    
    # Find the recovery code
    recovery_code = db.query(RecoveryCode).filter_by(
        user_id=user_id,
        code=code,
        used=False
    ).first()
    
    if not recovery_code:
        # Log the failed verification
        if hasattr(current_app, 'security'):
            security_logging = current_app.security.get("security_logging")
            if security_logging:
                security_logging.log_2fa_event(
                    "recovery_code_verify",
                    user_id,
                    success=False,
                    method="recovery",
                    error="Invalid code"
                )
        
        return jsonify({
            "success": False,
            "error": {
                "code": "invalid_code",
                "message": "Invalid recovery code"
            }
        }), 400
    
                # Mark the code as used
    recovery_code.used = True
    db.commit()
    
    # Log the successful verification
    if hasattr(current_app, 'security'):
        security_logging = current_app.security.get("security_logging")
        if security_logging:
            security_logging.log_2fa_event(
                "recovery_code_verify",
                user_id,
                success=True,
                method="recovery"
            )
    
    return jsonify({
        "success": True,
        "message": "Recovery code verified successfully"
    }) 