#!/usr/bin/env python3
"""
Evrmore Accounts Security Test Script

This script tests the security features of the Evrmore Accounts API.
It checks for security headers, rate limiting, and other security measures.
"""
import os
import sys
import time
import json
import argparse
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

# ANSI color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_success(message):
    """Print a success message in green"""
    print(f"{GREEN}✓ {message}{RESET}")

def print_failure(message):
    """Print a failure message in red"""
    print(f"{RED}✗ {message}{RESET}")

def print_warning(message):
    """Print a warning message in yellow"""
    print(f"{YELLOW}⚠ {message}{RESET}")

def print_info(message):
    """Print an info message in blue"""
    print(f"{BLUE}ℹ {message}{RESET}")

def print_header(message):
    """Print a header message in bold"""
    print(f"\n{BOLD}{message}{RESET}")
    print("=" * len(message))

class SecurityTester:
    """Test security features of the Evrmore Accounts API"""
    
    def __init__(self, base_url="http://localhost:5000", debug=False):
        """Initialize the security tester
        
        Args:
            base_url: Base URL of the API
            debug: Enable debug mode
        """
        self.base_url = base_url
        self.debug = debug
        self.session = requests.Session()
        self.results = {
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "total": 0
        }
        
        print_info(f"Testing API at {base_url}")
        print_info(f"Debug mode: {'enabled' if debug else 'disabled'}")
    
    def make_request(self, method, endpoint, data=None, headers=None, expected_status=None):
        """Make a request to the API
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            data: Request data
            headers: Request headers
            expected_status: Expected HTTP status code
            
        Returns:
            Response object
        """
        url = urljoin(self.base_url, endpoint)
        
        if self.debug:
            print_info(f"Making {method} request to {url}")
            if data:
                print_info(f"Data: {json.dumps(data)}")
            if headers:
                print_info(f"Headers: {json.dumps(headers)}")
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                headers=headers,
                timeout=10
            )
            
            if expected_status and response.status_code != expected_status:
                print_warning(f"Expected status {expected_status}, got {response.status_code}")
            
            if self.debug:
                print_info(f"Response status: {response.status_code}")
                try:
                    print_info(f"Response body: {json.dumps(response.json(), indent=2)}")
                except:
                    print_info(f"Response body: {response.text}")
            
            return response
        except requests.exceptions.RequestException as e:
            print_failure(f"Request failed: {str(e)}")
            return None
    
    def test_security_headers(self):
        """Test security headers in API responses"""
        print_header("Testing Security Headers")
        
        # Required security headers
        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": None,  # Any value is acceptable
            "Strict-Transport-Security": None,  # Any value is acceptable
            "Referrer-Policy": None,  # Any value is acceptable
        }
        
        # Make a request to the health endpoint
        response = self.make_request("GET", "/api/health")
        if not response:
            print_failure("Could not connect to API")
            self.results["failed"] += 1
            self.results["total"] += 1
            return
        
        # Check for required headers
        missing_headers = []
        for header, expected_value in required_headers.items():
            if header in response.headers:
                if expected_value is None:
                    print_success(f"Header {header} is present: {response.headers[header]}")
                elif isinstance(expected_value, list):
                    if response.headers[header] in expected_value:
                        print_success(f"Header {header} has valid value: {response.headers[header]}")
                    else:
                        print_failure(f"Header {header} has invalid value: {response.headers[header]}, expected one of {expected_value}")
                        missing_headers.append(header)
                elif response.headers[header] == expected_value:
                    print_success(f"Header {header} has expected value: {response.headers[header]}")
                else:
                    print_failure(f"Header {header} has unexpected value: {response.headers[header]}, expected {expected_value}")
                    missing_headers.append(header)
            else:
                print_failure(f"Header {header} is missing")
                missing_headers.append(header)
        
        # Update results
        if missing_headers:
            print_failure(f"Missing or invalid security headers: {', '.join(missing_headers)}")
            self.results["failed"] += 1
        else:
            print_success("All required security headers are present")
            self.results["passed"] += 1
        
        self.results["total"] += 1
    
    def test_rate_limiting(self):
        """Test rate limiting on API endpoints"""
        print_header("Testing Rate Limiting")
        
        # Endpoints to test
        endpoints = [
            "/api/health",
            "/api/challenge"
        ]
        
        for endpoint in endpoints:
            print_info(f"Testing rate limiting on {endpoint}")
            
            # Make multiple requests in parallel
            num_requests = 50
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(
                        self.make_request, 
                        "GET" if endpoint == "/api/health" else "POST",
                        endpoint,
                        {"evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"} if endpoint == "/api/challenge" else None
                    )
                    for _ in range(num_requests)
                ]
                
                responses = [future.result() for future in futures]
            
            # Check if any requests were rate limited
            rate_limited = [r for r in responses if r and r.status_code == 429]
            
            if rate_limited:
                print_success(f"Rate limiting is working: {len(rate_limited)} of {num_requests} requests were rate limited")
                
                # Check for Retry-After header
                if "Retry-After" in rate_limited[0].headers:
                    print_success(f"Retry-After header is present: {rate_limited[0].headers['Retry-After']}")
                else:
                    print_warning("Retry-After header is missing in rate limited responses")
                    self.results["warnings"] += 1
                
                self.results["passed"] += 1
            else:
                print_failure(f"Rate limiting is not working: all {num_requests} requests succeeded")
                self.results["failed"] += 1
            
            self.results["total"] += 1
            
            # Wait a bit before testing the next endpoint
            time.sleep(2)
    
    def test_jwt_security(self):
        """Test JWT token security"""
        print_header("Testing JWT Token Security")
        
        # Generate a challenge
        response = self.make_request(
            "POST",
            "/api/challenge",
            {"evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"}
        )
        
        if not response or response.status_code != 200:
            print_failure("Could not generate challenge")
            self.results["failed"] += 1
            self.results["total"] += 1
            return
        
        # Extract challenge
        challenge_data = response.json()
        challenge = challenge_data.get("challenge")
        
        if not challenge:
            print_failure("Challenge is missing from response")
            self.results["failed"] += 1
            self.results["total"] += 1
            return
        
        print_info(f"Generated challenge: {challenge}")
        
        # Try to authenticate with an invalid signature
        response = self.make_request(
            "POST",
            "/api/authenticate",
            {
                "evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc",
                "challenge": challenge,
                "signature": "invalid_signature"
            }
        )
        
        if not response:
            print_failure("Authentication request failed")
            self.results["failed"] += 1
            self.results["total"] += 1
            return
        
        # Check if authentication was rejected
        if response.status_code == 401:
            print_success("Authentication with invalid signature was correctly rejected")
            self.results["passed"] += 1
        else:
            print_failure(f"Authentication with invalid signature returned status {response.status_code}, expected 401")
            self.results["failed"] += 1
        
        self.results["total"] += 1
        
        # Try to use an invalid token
        response = self.make_request(
            "GET",
            "/api/validate",
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        if not response:
            print_failure("Token validation request failed")
            self.results["failed"] += 1
            self.results["total"] += 1
            return
        
        # Check if token validation was rejected
        if response.status_code == 401 or response.status_code == 422:
            print_success("Invalid token was correctly rejected")
            self.results["passed"] += 1
        else:
            print_failure(f"Invalid token validation returned status {response.status_code}, expected 401 or 422")
            self.results["failed"] += 1
        
        self.results["total"] += 1
    
    def test_error_handling(self):
        """Test standardized error handling"""
        print_header("Testing Error Handling")
        
        # Test endpoints that should return errors
        test_cases = [
            {
                "method": "POST",
                "endpoint": "/api/challenge",
                "data": {},  # Missing evrmore_address
                "expected_status": 400
            },
            {
                "method": "GET",
                "endpoint": "/api/nonexistent",
                "expected_status": 404
            },
            {
                "method": "POST",
                "endpoint": "/api/health",  # Method not allowed
                "expected_status": 405
            }
        ]
        
        for test_case in test_cases:
            print_info(f"Testing {test_case['method']} {test_case['endpoint']}")
            
            response = self.make_request(
                test_case["method"],
                test_case["endpoint"],
                test_case.get("data"),
                expected_status=test_case["expected_status"]
            )
            
            if not response:
                print_failure("Request failed")
                self.results["failed"] += 1
                self.results["total"] += 1
                continue
            
            # Check if status code matches expected
            if response.status_code == test_case["expected_status"]:
                print_success(f"Returned expected status code: {response.status_code}")
            else:
                print_failure(f"Returned unexpected status code: {response.status_code}, expected {test_case['expected_status']}")
                self.results["failed"] += 1
                self.results["total"] += 1
                continue
            
            # Check if response has standardized error format
            try:
                error_data = response.json()
                
                if "success" in error_data and error_data["success"] is False:
                    print_success("Response has 'success: false' field")
                else:
                    print_failure("Response is missing 'success: false' field")
                    self.results["failed"] += 1
                    self.results["total"] += 1
                    continue
                
                if "error" in error_data and isinstance(error_data["error"], dict):
                    print_success("Response has 'error' object")
                    
                    error_obj = error_data["error"]
                    
                    if "code" in error_obj and isinstance(error_obj["code"], str):
                        print_success(f"Error has 'code' field: {error_obj['code']}")
                    else:
                        print_failure("Error is missing 'code' field")
                        self.results["warnings"] += 1
                    
                    if "message" in error_obj and isinstance(error_obj["message"], str):
                        print_success(f"Error has 'message' field: {error_obj['message']}")
                    else:
                        print_failure("Error is missing 'message' field")
                        self.results["warnings"] += 1
                    
                    self.results["passed"] += 1
                else:
                    print_failure("Response is missing 'error' object")
                    self.results["failed"] += 1
            except ValueError:
                print_failure("Response is not valid JSON")
                self.results["failed"] += 1
            
            self.results["total"] += 1
    
    def run_tests(self):
        """Run all security tests"""
        print_header("Starting Security Tests")
        
        # Run tests
        self.test_security_headers()
        self.test_rate_limiting()
        self.test_jwt_security()
        self.test_error_handling()
        
        # Print summary
        print_header("Test Summary")
        print(f"Total tests: {self.results['total']}")
        print(f"{GREEN}Passed: {self.results['passed']}{RESET}")
        print(f"{RED}Failed: {self.results['failed']}{RESET}")
        print(f"{YELLOW}Warnings: {self.results['warnings']}{RESET}")
        
        # Return success if all tests passed
        return self.results["failed"] == 0

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Test Evrmore Accounts API security")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL of the API")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    tester = SecurityTester(args.url, args.debug)
    success = tester.run_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 