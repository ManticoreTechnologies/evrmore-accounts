#!/usr/bin/env python3
"""
Evrmore Accounts Backend - Comprehensive Test & Audit Script

This script performs a thorough evaluation of all Evrmore Accounts backend features,
security measures, and performance characteristics.

Usage:
    python3 test_backend.py [--url URL] [--debug]

Options:
    --url URL    Base URL of the Evrmore Accounts API (default: http://localhost:5000)
    --debug      Enable detailed debug output

Author: Manticore Technologies <dev@manticore.technology>
"""

import os
import sys
import json
import time
import logging
import argparse
import requests
import concurrent.futures
from datetime import datetime, timedelta
import uuid
import pyotp
import hashlib
import hmac
from urllib.parse import urljoin
import colorama
from colorama import Fore, Style

# Set TESTING environment variable for the test suite
# This ensures that the backend knows it's being tested
os.environ["TESTING"] = "true"

# Initialize colorama
colorama.init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("evrmore_accounts_test")

def check_server_running(base_url):
    """Check if the server is running before proceeding with tests"""
    health_url = urljoin(base_url, "/api/health")
    print(f"{Fore.BLUE}Checking if server is running at {base_url}...{Style.RESET_ALL}")
    
    try:
        response = requests.get(health_url, timeout=3)
        if response.status_code == 200:
            print(f"{Fore.GREEN}Server is running! ✓{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}Server returned status code {response.status_code}! ✗{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}Cannot connect to server! ✗{Style.RESET_ALL}")
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}Connection timed out! ✗{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error checking server: {str(e)} ✗{Style.RESET_ALL}")
    
    print()
    print(f"{Fore.YELLOW}Make sure the server is running with:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}python3 run.py{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}# or{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}python3 -m evrmore_accounts.app{Style.RESET_ALL}")
    print()
    
    return False

# Available Evrmore test addresses and private keys
from evrmore_rpc import EvrmoreClient
rpc = EvrmoreClient()

TEST_ACCOUNTS = [
    {
        "address": rpc.getnewaddress()
    },
    {
        "address": rpc.getnewaddress()
    }
]

class EvrmoreAccountsTest:
    """Test suite for Evrmore Accounts backend"""
    
    def __init__(self, base_url="http://localhost:5000", debug=False):
        """Initialize the test suite
        
        Args:
            base_url: Base URL of the Evrmore Accounts API
            debug: Enable debug mode
        """
        self.base_url = base_url
        self.debug = debug
        self.api_url = urljoin(base_url, "/api/")
        self.auth_url = urljoin(base_url, "/api/auth/")
        self.session = requests.Session()
        self.access_token = None
        self.challenge = None
        self.test_user = TEST_ACCOUNTS[0]
        
        if debug:
            logger.setLevel(logging.DEBUG)
        
        logger.info(f"Initialized test suite for {self.api_url}")
        
    def log_success(self, message):
        """Log success message"""
        print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
        
    def log_failure(self, message):
        """Log failure message"""
        print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")
        
    def log_warning(self, message):
        """Log warning message"""
        print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")
        
    def log_info(self, message):
        """Log info message"""
        print(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")
    
    def make_request(self, method, endpoint, data=None, headers=None, auth=True):
        """Make API request
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint
            data: Request data
            headers: Request headers
            auth: Include authentication token
            
        Returns:
            Response object
        """
        # Determine the correct base URL based on the endpoint pattern
        if endpoint.startswith("auth/") or endpoint.startswith("auth/2fa/"):
            # Strip "auth/" from the beginning if present, as it's already in auth_url
            if endpoint.startswith("auth/"):
                endpoint = endpoint[5:]
            url = urljoin(self.auth_url, endpoint)
        else:
            url = urljoin(self.api_url, endpoint)
        
        if headers is None:
            headers = {}
            
        if auth and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
            
        if self.debug:
            logger.debug(f"Request: {method} {url}")
            if data:
                logger.debug(f"Data: {json.dumps(data, indent=2)}")
        
        response = self.session.request(
            method=method,
            url=url,
            json=data,
            headers=headers
        )
        
        if self.debug:
            logger.debug(f"Response: {response.status_code}")
            try:
                logger.debug(f"Content: {json.dumps(response.json(), indent=2)}")
            except:
                logger.debug(f"Content: {response.text}")
        
        return response
    
    def test_health(self):
        """Test API health endpoint"""
        self.log_info("Testing API health...")
        try:
            response = self.make_request("GET", "health", auth=False)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "ok":
                    self.log_success("Health check passed")
                    return True
                else:
                    self.log_failure(f"Health check failed: {data}")
            else:
                self.log_failure(f"Health check failed with status {response.status_code}")
        except Exception as e:
            self.log_failure(f"Health check error: {str(e)}")
        
        return False
    
    def test_challenge_generation(self):
        """Test challenge generation"""
        self.log_info("Testing challenge generation...")
        
        # Adding a delay to avoid rate limiting
        time.sleep(2)
        
        try:
            data = {"evrmore_address": self.test_user["address"]}
            response = self.make_request("POST", "auth/challenge", data=data, auth=False)
            
            if response.status_code == 200:
                challenge_data = response.json()
                if "challenge" in challenge_data and "expires_at" in challenge_data:
                    self.challenge = challenge_data["challenge"]
                    self.log_success(f"Challenge generated: {self.challenge}")
                    return True
                else:
                    self.log_failure(f"Invalid challenge response: {challenge_data}")
            else:
                self.log_failure(f"Challenge generation failed with status {response.status_code}")
                if response.text:
                    self.log_failure(f"Error: {response.text}")
        except Exception as e:
            self.log_failure(f"Challenge generation error: {str(e)}")
        
        return False
    
    def sign_message(self, address, message):
        """Sign a message with Evrmore wallet
        
        In a real implementation, this would use evrmore-cli or a wallet API.
        For testing, we'll simulate this by printing the command.
        
        Args:
            address: Evrmore address
            message: Message to sign
            
        Returns:
            Simulated signature
        """
        # In a real test with actual evrmore-cli:
        # import subprocess
        # cmd = ["evrmore-cli", "signmessage", address, message]
        # result = subprocess.run(cmd, capture_output=True, text=True)
        # signature = result.stdout.strip()
        # return signature
        
        # For testing purposes, we'll just create a dummy signature
        # In a real scenario, you would use actual evrmore-cli or SDK
        from evrmore_rpc import EvrmoreClient
        rpc = EvrmoreClient()
        
        # Use sign_message instead of signmessage (method name fixed)
        signed_message = rpc.signmessage(address, message)
        key = self.test_user.get("private_key", "")
        dummy_sig = hashlib.sha256(f"{key}:{message}".encode()).hexdigest()
        
        self.log_info(f"Command to sign message: evrmore-cli signmessage {address} \"{message}\"")
        self.log_info(f"Using signature for testing: {signed_message}")
        return signed_message
    
    def test_authentication(self):
        """Test authentication with challenge and signature"""
        self.log_info("Testing authentication...")
        
        if not self.challenge:
            self.log_failure("No challenge available for authentication")
            return False
        
        try:
            # Sign the challenge
            signature = self.sign_message(self.test_user["address"], self.challenge)
            
            # Authenticate with signed challenge
            data = {
                "evrmore_address": self.test_user["address"],
                "challenge": self.challenge,
                "signature": signature
            }
            
            response = self.make_request("POST", "auth/authenticate", data=data, auth=False)
            
            if response.status_code == 200:
                auth_data = response.json()
                if "token" in auth_data and "user" in auth_data:
                    self.access_token = auth_data["token"]
                    self.log_success(f"Authentication successful, token received")
                    return True
                else:
                    self.log_failure(f"Invalid authentication response: {auth_data}")
            else:
                self.log_failure(f"Authentication failed with status {response.status_code}")
                try:
                    error_data = response.json()
                    self.log_failure(f"Error: {error_data}")
                except:
                    self.log_failure(f"Error: {response.text}")
        except Exception as e:
            self.log_failure(f"Authentication error: {str(e)}")
        
        return False
    
    def test_token_validation(self):
        """Test token validation"""
        self.log_info("Testing token validation...")
        
        if not self.access_token:
            self.log_failure("No access token available for validation")
            return False
        
        try:
            response = self.make_request("GET", "auth/validate")
            
            if response.status_code == 200:
                data = response.json()
                if data.get("valid") == True and "user" in data:
                    self.log_success("Token validation successful")
                    return True
                else:
                    self.log_failure(f"Invalid token validation response: {data}")
            else:
                self.log_failure(f"Token validation failed with status {response.status_code}")
        except Exception as e:
            self.log_failure(f"Token validation error: {str(e)}")
        
        return False
    
    def test_user_profile(self):
        """Test user profile endpoint"""
        self.log_info("Testing user profile...")
        
        if not self.access_token:
            self.log_failure("No access token available for user profile")
            return False
        
        try:
            response = self.make_request("GET", "user")
            
            if response.status_code == 200:
                response_data = response.json()
                # Check if response contains user data directly or nested in a 'user' field
                if "success" in response_data and "user" in response_data:
                    # Nested user data structure
                    user_data = response_data["user"]
                    if "id" in user_data and "evrmore_address" in user_data:
                        self.log_success(f"User profile retrieved successfully")
                        # Print user details
                        self.log_info(f"User ID: {user_data.get('id')}")
                        self.log_info(f"Evrmore Address: {user_data.get('evrmore_address')}")
                        return True
                    else:
                        self.log_failure(f"Invalid user data in nested response: {user_data}")
                elif "id" in response_data and "evrmore_address" in response_data:
                    # Direct user data structure
                    self.log_success(f"User profile retrieved successfully")
                    # Print user details
                    self.log_info(f"User ID: {response_data.get('id')}")
                    self.log_info(f"Evrmore Address: {response_data.get('evrmore_address')}")
                    return True
                else:
                    self.log_failure(f"Invalid user profile response: {response_data}")
            else:
                self.log_failure(f"User profile retrieval failed with status {response.status_code}")
        except Exception as e:
            self.log_failure(f"User profile error: {str(e)}")
        
        return False
    
    def test_2fa_setup(self):
        """Test 2FA setup flow"""
        self.log_info("Testing 2FA setup...")
        
        if not self.access_token:
            self.log_failure("No access token available for 2FA setup")
            return False
        
        try:
            # Step 1: Get TOTP setup information
            response = self.make_request("POST", "auth/2fa/totp/setup")
            
            if response.status_code != 200:
                self.log_failure(f"2FA setup failed with status {response.status_code}")
                return False
            
            setup_data = response.json()
            if "secret" not in setup_data or "provisioning_uri" not in setup_data:
                self.log_failure(f"Invalid 2FA setup response: {setup_data}")
                return False
            
            secret = setup_data["secret"]
            self.log_success(f"2FA setup information received")
            self.log_info(f"TOTP Secret: {secret}")
            self.log_info(f"Provisioning URI: {setup_data.get('provisioning_uri')}")
            
            # Step 2: Generate and verify TOTP code
            totp = pyotp.TOTP(secret)
            code = totp.now()
            self.log_info(f"Generated TOTP code: {code}")
            
            verify_response = self.make_request("POST", "auth/2fa/totp/verify", data={"code": code})
            
            if verify_response.status_code != 200:
                self.log_failure(f"2FA verification failed with status {verify_response.status_code}")
                return False
            
            verify_data = verify_response.json()
            if not verify_data.get("valid", False):
                self.log_failure(f"2FA verification failed: {verify_data}")
                return False
            
            self.log_success(f"2FA verification successful")
            
            # Step 3: Enable 2FA
            enable_response = self.make_request("POST", "auth/2fa/totp/enable", data={"code": code})
            
            if enable_response.status_code != 200:
                self.log_failure(f"2FA enable failed with status {enable_response.status_code}")
                return False
            
            enable_data = enable_response.json()
            if not enable_data.get("success", False):
                self.log_failure(f"2FA enable failed: {enable_data}")
                return False
            
            self.log_success(f"2FA enabled successfully")
            
            # Step 4: Get 2FA status
            status_response = self.make_request("GET", "auth/2fa/status")
            
            if status_response.status_code != 200:
                self.log_failure(f"2FA status check failed with status {status_response.status_code}")
                return False
            
            status_data = status_response.json()
            
            if not status_data.get("totp", {}).get("enabled", False):
                self.log_failure(f"2FA status does not show TOTP as enabled: {status_data}")
                return False
            
            self.log_success(f"2FA status shows TOTP is enabled")
            
            # Step 5: Disable 2FA (cleanup)
            disable_response = self.make_request("POST", "auth/2fa/totp/disable", data={"code": code})
            
            if disable_response.status_code != 200:
                self.log_failure(f"2FA disable failed with status {disable_response.status_code}")
                return False
            
            disable_data = disable_response.json()
            if not disable_data.get("success", False):
                self.log_failure(f"2FA disable failed: {disable_data}")
                return False
            
            self.log_success(f"2FA disabled successfully (cleanup)")
            
            return True
            
        except Exception as e:
            self.log_failure(f"2FA testing error: {str(e)}")
        
        return False
    
    def test_logout(self):
        """Test logout endpoint"""
        self.log_info("Testing logout...")
        
        if not self.access_token:
            self.log_failure("No access token available for logout")
            return False
        
        try:
            response = self.make_request("POST", "auth/logout")
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success") == True:
                    self.log_success("Logout successful")
                    self.access_token = None
                    return True
                else:
                    self.log_failure(f"Invalid logout response: {data}")
            else:
                self.log_failure(f"Logout failed with status {response.status_code}")
        except Exception as e:
            self.log_failure(f"Logout error: {str(e)}")
        
        return False
    
    def test_rate_limiting(self):
        """Test rate limiting by sending multiple requests"""
        self.log_info("Testing rate limiting...")
        
        # Wait a bit to ensure rate limits are reset between tests
        time.sleep(3)
        
        try:
            # Send multiple requests in quick succession
            data = {"evrmore_address": self.test_user["address"]}
            success_count = 0
            rate_limited_count = 0
            
            # Make more requests with no delay to ensure we hit the rate limit
            for i in range(30):
                response = self.make_request("POST", "auth/challenge", data=data, auth=False)
                
                if response.status_code == 200:
                    success_count += 1
                elif response.status_code == 429:  # Too Many Requests
                    rate_limited_count += 1
                    self.log_info(f"Rate limited after {success_count} requests")
                    break
                else:
                    self.log_warning(f"Unexpected status code {response.status_code}")
                
                # No delay - we want to trigger rate limiting
            
            # If still no rate limiting, try another endpoint
            if rate_limited_count == 0:
                self.log_info("Trying auth endpoint for rate limiting...")
                for i in range(20):
                    response = self.make_request("POST", "auth/logout", auth=False)
                    if response.status_code == 429:
                        rate_limited_count += 1
                        self.log_info(f"Rate limited on auth endpoint after {i} requests")
                        break
            
            # Add a delay to let rate limits reset for upcoming tests
            time.sleep(5)
            
            if rate_limited_count > 0:
                self.log_success(f"Rate limiting is working ({success_count} successful requests before limiting)")
                return True
            else:
                self.log_warning("No rate limiting detected - this might be a security issue")
                return False
            
        except Exception as e:
            self.log_failure(f"Rate limiting test error: {str(e)}")
        
        return False
    
    def test_security_headers(self):
        """Test security headers in responses"""
        self.log_info("Testing security headers...")
        
        try:
            response = self.make_request("GET", "health", auth=False)
            
            headers = response.headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": None  # Any value is acceptable
            }
            
            missing_headers = []
            for header, expected_value in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                elif expected_value is not None and headers[header] != expected_value:
                    self.log_warning(f"Header {header} has value {headers[header]}, expected {expected_value}")
            
            if missing_headers:
                self.log_warning(f"Missing security headers: {', '.join(missing_headers)}")
                return False
            else:
                self.log_success("All security headers are present")
                return True
            
        except Exception as e:
            self.log_failure(f"Security headers test error: {str(e)}")
        
        return False
    
    def test_jwt_security(self):
        """Test JWT token security"""
        self.log_info("Testing JWT token security...")
        
        if not self.access_token:
            # Generate a new token if needed
            if not self.test_challenge_generation() or not self.test_authentication():
                self.log_failure("Could not obtain JWT token for testing")
                return False
        
        try:
            # Test 1: Try a modified token
            parts = self.access_token.split('.')
            if len(parts) != 3:
                self.log_failure(f"Invalid JWT token format")
                return False
            
            # Modify the payload slightly
            modified_token = f"{parts[0]}.{parts[1]}x.{parts[2]}"
            
            headers = {"Authorization": f"Bearer {modified_token}"}
            response = self.make_request("GET", "user", headers=headers, auth=False)
            
            if response.status_code != 401 and response.status_code != 422:
                self.log_failure(f"Modified token test failed: got status {response.status_code}, expected 401 or 422")
                return False
            
            self.log_success("Modified token correctly rejected")
            
            # Test 2: Try an expired token
            # We can't easily test this without waiting, so we'll skip for now
            
            # Test 3: Try accessing a protected endpoint without a token
            no_auth_response = self.make_request("GET", "user", auth=False)
            
            if no_auth_response.status_code != 401:
                self.log_failure(f"No token test failed: got status {no_auth_response.status_code}, expected 401")
                return False
            
            self.log_success("Protected endpoint correctly requires authentication")
            
            return True
            
        except Exception as e:
            self.log_failure(f"JWT security test error: {str(e)}")
        
        return False
    
    def test_cors_headers(self):
        """Test CORS headers in responses"""
        self.log_info("Testing CORS headers...")
        
        try:
            # Send an OPTIONS request with Origin header
            headers = {
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization"
            }
            
            response = self.session.options(
                url=urljoin(self.api_url, "health"),
                headers=headers
            )
            
            cors_headers = [
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Methods",
                "Access-Control-Allow-Headers",
                "Access-Control-Allow-Credentials"
            ]
            
            missing_headers = []
            for header in cors_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.log_warning(f"Missing CORS headers: {', '.join(missing_headers)}")
                return False
            else:
                self.log_success("All CORS headers are present")
                return True
            
        except Exception as e:
            self.log_failure(f"CORS headers test error: {str(e)}")
        
        return False
    
    def reset_server(self):
        """Reset the server state to avoid rate limiting between tests"""
        self.log_info("Resetting server state...")
        try:
            # Make a request to reset the rate limiter
            response = self.make_request("GET", "health?reset=true", auth=False)
            # Wait a moment for the reset to take effect
            time.sleep(1)
            return True
        except Exception as e:
            self.log_warning(f"Failed to reset server state: {str(e)}")
            return False
    
    def run_tests(self):
        """Run all tests"""
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"EVRMORE ACCOUNTS BACKEND TEST SUITE")
        print(f"{'=' * 80}{Style.RESET_ALL}\n")
        
        print(f"Testing API at: {self.api_url}")
        print(f"Test Account: {self.test_user['address']}")
        print(f"Debug Mode: {'Enabled' if self.debug else 'Disabled'}")
        print()
        
        # Basic API health and functionality
        tests = [
            ("API Health", self.test_health),
            ("Security Headers", self.test_security_headers),
            ("CORS Headers", self.test_cors_headers),
            ("Challenge Generation", self.test_challenge_generation),
            ("Authentication", self.test_authentication),
            ("Token Validation", self.test_token_validation),
            ("User Profile", self.test_user_profile),
            ("2FA Setup", self.test_2fa_setup),
            ("JWT Security", self.test_jwt_security),
            ("Logout", self.test_logout),
            # Run rate limiting test last since it will affect other tests
            ("Rate Limiting", self.test_rate_limiting)
        ]
        
        results = []
        for i, (name, test_func) in enumerate(tests):
            print(f"\n{Fore.CYAN}▶ Testing: {name}{Style.RESET_ALL}")
            
            # Reset server state before tests that are susceptible to rate limiting
            if name in ["Challenge Generation", "Authentication", "JWT Security"]:
                self.reset_server()
                # Add extra delay for these critical tests
                time.sleep(2)
            
            start_time = time.time()
            success = test_func()
            duration = time.time() - start_time
            
            results.append({
                "name": name,
                "success": success,
                "duration": duration
            })
            
            print(f"{Fore.CYAN}  Completed in {duration:.2f}s{Style.RESET_ALL}")
        
        # Print summary
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"TEST SUMMARY")
        print(f"{'=' * 80}{Style.RESET_ALL}\n")
        
        passed = sum(1 for r in results if r["success"])
        failed = len(results) - passed
        
        for result in results:
            status = f"{Fore.GREEN}PASS" if result["success"] else f"{Fore.RED}FAIL"
            print(f"{status}{Style.RESET_ALL} | {result['name']} ({result['duration']:.2f}s)")
        
        print(f"\nTests: {len(results)}, Passed: {passed}, Failed: {failed}")
        
        if failed == 0:
            print(f"\n{Fore.GREEN}All tests passed successfully!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}{failed} tests failed.{Style.RESET_ALL}")
        
        return failed == 0

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Evrmore Accounts Backend Test Suite")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL of the Evrmore Accounts API")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    # Check if server is running before starting tests
    if not check_server_running(args.url):
        return 1
    
    # Initialize and run tests
    test_suite = EvrmoreAccountsTest(
        base_url=args.url,
        debug=args.debug
    )
    
    return 0 if test_suite.run_tests() else 1

if __name__ == "__main__":
    sys.exit(main()) 