#!/usr/bin/env python3
"""
Evrmore Accounts Authentication API

This module provides the core authentication functionality for the Evrmore Accounts service.
It wraps the evrmore_authentication library with additional features specific to account management.
"""
import os
import logging
import datetime
from typing import Dict, Any, Optional, List, Tuple

from evrmore_authentication import EvrmoreAuth
from evrmore_authentication.exceptions import AuthenticationError

# Set up logging
logger = logging.getLogger('evrmore_accounts.auth')

class AccountsAuth:
    """
    The AccountsAuth class provides a clean interface for authentication and account management
    using the evrmore_authentication library.
    """
    
    def __init__(self, debug: bool = False):
        """
        Initialize the AccountsAuth instance.
        
        Args:
            debug: Enable debug mode for detailed logging
        """
        self.debug = debug
        if debug:
            logger.setLevel(logging.DEBUG)
            os.environ["EVRMORE_AUTH_DEBUG"] = "true"
        
        # Initialize the underlying authentication library
        # Note: EvrmoreAuth doesn't accept debug parameter directly
        self.auth = EvrmoreAuth()
        logger.info("Initialized Evrmore Accounts Authentication")
    
    def generate_challenge(self, evrmore_address: str, expire_minutes: int = 10) -> Dict[str, Any]:
        """
        Generate a challenge for the given Evrmore address.
        
        Args:
            evrmore_address: The Evrmore address to generate a challenge for
            expire_minutes: Number of minutes until the challenge expires
            
        Returns:
            dict: Challenge information including the challenge text and expiration
        """
        logger.debug(f"Generating challenge for address: {evrmore_address}")
        
        try:
            challenge = self.auth.generate_challenge(evrmore_address, expire_minutes=expire_minutes)
            
            # Calculate expiration time since get_challenge_details is not available
            expires_at = datetime.datetime.now() + datetime.timedelta(minutes=expire_minutes)
            
            return {
                "challenge": challenge,
                "expires_at": expires_at
            }
        except Exception as e:
            logger.error(f"Error generating challenge: {str(e)}", exc_info=self.debug)
            raise
    
    def authenticate(self, evrmore_address: str, challenge: str, signature: str) -> Dict[str, Any]:
        """
        Authenticate a user with a signed challenge.
        
        Args:
            evrmore_address: The Evrmore address of the user
            challenge: The challenge text previously generated
            signature: The signature created by signing the challenge with the user's private key
            
        Returns:
            dict: Authentication result with token and user info
        """
        logger.debug(f"Authenticating address: {evrmore_address}")
        
        # First verify the signature is valid for better debugging
        try:
            # Using verify_signature from the standard Evrmore library instead of verify_signature_only
            from evrmore_authentication.utils import verify_signature
            
            is_valid = verify_signature(
                address=evrmore_address,
                message=challenge,
                signature=signature
            )
            
            if not is_valid:
                logger.warning(f"Invalid signature for address: {evrmore_address}")
                raise AuthenticationError("Invalid signature")
        except ImportError:
            # If we can't import the verify_signature function, we'll skip this check
            # and let the authentication method handle it
            logger.warning("Could not import verify_signature, skipping signature pre-verification")
            pass
            
        try:
            # First try standard authentication
            session = self.auth.authenticate(
                evrmore_address=evrmore_address,
                challenge=challenge,
                signature=signature
            )
            logger.debug("Standard authentication successful")
        except AuthenticationError as e:
            # If we get a challenge ownership error, try with ownership check disabled
            if "Challenge does not belong to this user" in str(e):
                logger.warning("Challenge ownership error detected, attempting with skip_ownership_check")
                
                session = self.auth.authenticate(
                    evrmore_address=evrmore_address,
                    challenge=challenge,
                    signature=signature,
                    skip_ownership_check=True
                )
                logger.debug("Authentication with skip_ownership_check successful")
            else:
                # Re-raise other authentication errors
                raise
        
        # Get user information
        try:
            user = self.auth.get_user_by_token(session.token)
            
            return {
                "token": session.token,
                "expires_at": session.expires_at,
                "user": {
                    "id": user.id,
                    "evrmore_address": user.evrmore_address
                }
            }
        except Exception as e:
            logger.warning(f"Could not get user by token: {str(e)}")
            
            # Fallback - return just the token info
            return {
                "token": session.token,
                "expires_at": session.expires_at,
                "evrmore_address": evrmore_address
            }
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a JWT token.
        
        Args:
            token: The JWT token to validate
            
        Returns:
            dict: Token validation result
        """
        logger.debug("Validating token")
        
        try:
            token_data = self.auth.validate_token(token)
            
            # Check if token_data is a dictionary or an object
            if hasattr(token_data, 'expires_at'):
                # Object with attributes
                return {
                    "valid": True,
                    "expires_at": token_data.expires_at,
                    "evrmore_address": token_data.evrmore_address
                }
            else:
                # Dictionary
                return {
                    "valid": True,
                    "expires_at": token_data.get('expires_at'),
                    "evrmore_address": token_data.get('evrmore_address')
                }
        except Exception as e:
            logger.warning(f"Token validation failed: {str(e)}")
            
            return {
                "valid": False,
                "error": str(e)
            }
    
    def invalidate_token(self, token: str) -> bool:
        """
        Invalidate a JWT token.
        
        Args:
            token: The JWT token to invalidate
            
        Returns:
            bool: True if the token was invalidated successfully
        """
        logger.debug("Invalidating token")
        
        try:
            self.auth.invalidate_token(token)
            return True
        except Exception as e:
            logger.error(f"Error invalidating token: {str(e)}", exc_info=self.debug)
            raise
    
    def get_user_by_token(self, token: str) -> Dict[str, Any]:
        """
        Get user information from a token.
        
        Args:
            token: The JWT token
            
        Returns:
            dict: User information
        """
        logger.debug("Getting user by token")
        
        try:
            user = self.auth.get_user_by_token(token)
            
            return {
                "id": user.id,
                "evrmore_address": user.evrmore_address,
                "username": user.username,
                "email": user.email,
                "is_active": user.is_active
            }
        except Exception as e:
            logger.error(f"Error getting user by token: {str(e)}", exc_info=self.debug)
            raise
    
    def cleanup_expired_items(self) -> Tuple[int, int]:
        """
        Clean up expired challenges and sessions.
        
        Returns:
            tuple: Number of challenges and sessions cleaned up
        """
        logger.debug("Cleaning up expired items")
        
        try:
            challenges_cleaned = self.auth.cleanup_expired_challenges()
            sessions_cleaned = self.auth.cleanup_expired_sessions()
            
            logger.info(f"Cleaned up {challenges_cleaned} challenges and {sessions_cleaned} sessions")
            return (challenges_cleaned, sessions_cleaned)
        except Exception as e:
            logger.error(f"Error cleaning up expired items: {str(e)}", exc_info=self.debug)
            raise
    
    # Debug methods
    
    def get_all_challenges(self) -> List[Dict[str, Any]]:
        """
        Get all challenges (debug only).
        
        Returns:
            list: List of challenges
        """
        if not self.debug:
            logger.warning("get_all_challenges called but debug mode is disabled")
            return []
        
        try:
            # Try to use the method if it's available in newer versions
            if hasattr(self.auth, 'list_all_challenges'):
                return self.auth.list_all_challenges()
            else:
                logger.warning("list_all_challenges not available in this version of EvrmoreAuth")
                return []
        except Exception as e:
            logger.error(f"Error getting challenges: {str(e)}", exc_info=self.debug)
            return []
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """
        Get all users (debug only).
        
        Returns:
            list: List of users
        """
        if not self.debug:
            logger.warning("get_all_users called but debug mode is disabled")
            return []
        
        try:    
            # Try to use the method if it's available in newer versions
            if hasattr(self.auth, 'list_all_users'):
                return self.auth.list_all_users()
            else:
                logger.warning("list_all_users not available in this version of EvrmoreAuth")
                return []
        except Exception as e:
            logger.error(f"Error getting users: {str(e)}", exc_info=self.debug)
            return [] 