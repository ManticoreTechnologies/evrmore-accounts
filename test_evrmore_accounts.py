#!/usr/bin/env python3
"""
Evrmore Accounts Test Script

This script tests the Evrmore Accounts library functionality.
"""
import os
import logging
from evrmore_accounts.api import AccountsAuth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("test_script")

def main():
    """Main test function"""
    logger.info("Testing Evrmore Accounts library...")
    
    # Enable debug mode for detailed logging
    auth = AccountsAuth(debug=True)
    
    # Test addresses (replace with actual Evrmore addresses if testing with real wallets)
    test_address = "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"
    
    try:
        # 1. Generate a challenge
        logger.info(f"Generating challenge for address: {test_address}")
        challenge_result = auth.generate_challenge(test_address)
        challenge_text = challenge_result["challenge"]
        expires_at = challenge_result["expires_at"]
        
        logger.info(f"Challenge generated: {challenge_text}")
        logger.info(f"Challenge expires at: {expires_at}")
        
        # In a real scenario, the user would sign this challenge with their wallet
        # For testing, we can't sign without a wallet, so we'll just print the challenge
        
        logger.info("To authenticate, a user would sign this challenge with their wallet.")
        logger.info("Example command: evrmore-cli signmessage \"EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc\" \"" + challenge_text + "\"")
        
        # 2. Get all challenges (debug function)
        logger.info("Retrieving all challenges:")
        challenges = auth.get_all_challenges()
        logger.info(f"Found {len(challenges)} challenges")
        
        # 3. Get all users (debug function)
        logger.info("Retrieving all users:")
        users = auth.get_all_users()
        logger.info(f"Found {len(users)} users")
        
        logger.info("Test completed successfully")
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main() 