#!/usr/bin/env python3
"""
Evrmore Accounts Server Healthcheck

This script checks if the Evrmore Accounts server is running and responding properly.
It performs a basic health check and prints the status.

Usage:
    python3 healthcheck.py [--url URL]

Options:
    --url URL    Base URL of the Evrmore Accounts API (default: http://localhost:5000)
"""

import argparse
import json
import sys
import requests
from urllib.parse import urljoin

def green(text):
    """Return text in green color"""
    return f"\033[92m{text}\033[0m"

def red(text):
    """Return text in red color"""
    return f"\033[91m{text}\033[0m"

def yellow(text):
    """Return text in yellow color"""
    return f"\033[93m{text}\033[0m"

def blue(text):
    """Return text in blue color"""
    return f"\033[94m{text}\033[0m"

def check_server_health(base_url):
    """Check if the server is running and healthy
    
    Args:
        base_url: Base URL of the Evrmore Accounts API
        
    Returns:
        True if server is healthy, False otherwise
    """
    api_url = urljoin(base_url, "/api/health")
    
    try:
        print(f"Checking server health at {blue(api_url)}...")
        response = requests.get(api_url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "ok":
                print(green("✓ Server is healthy!"))
                print(f"  Service: {data.get('service')}")
                print(f"  Version: {data.get('version')}")
                return True
            else:
                print(yellow(f"⚠ Server reports non-OK status: {data.get('status')}"))
        else:
            print(red(f"✗ Server returned status code {response.status_code}"))
            
    except requests.exceptions.ConnectionError:
        print(red("✗ Connection error - server is not running or not accessible"))
    except requests.exceptions.Timeout:
        print(red("✗ Connection timeout - server is taking too long to respond"))
    except Exception as e:
        print(red(f"✗ Error checking server health: {str(e)}"))
    
    return False

def check_challenge_endpoint(base_url):
    """Check if the challenge endpoint is working
    
    Args:
        base_url: Base URL of the Evrmore Accounts API
        
    Returns:
        True if endpoint is working, False otherwise
    """
    api_url = urljoin(base_url, "/api/challenge")
    test_address = "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"
    
    try:
        print(f"Testing challenge endpoint at {blue(api_url)}...")
        response = requests.post(
            api_url, 
            json={"evrmore_address": test_address},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if "challenge" in data and "expires_at" in data:
                print(green("✓ Challenge endpoint is working!"))
                return True
            else:
                print(yellow(f"⚠ Challenge endpoint returned unexpected data: {data}"))
        else:
            print(red(f"✗ Challenge endpoint returned status code {response.status_code}"))
            if response.text:
                print(red(f"  Error: {response.text}"))
            
    except Exception as e:
        print(red(f"✗ Error testing challenge endpoint: {str(e)}"))
    
    return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Evrmore Accounts Server Healthcheck")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL of the Evrmore Accounts API")
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("EVRMORE ACCOUNTS SERVER HEALTHCHECK")
    print("=" * 80)
    print()
    
    # Check server health
    server_healthy = check_server_health(args.url)
    
    if server_healthy:
        # Check challenge endpoint
        challenge_working = check_challenge_endpoint(args.url)
        
        if challenge_working:
            print(f"\n{green('All checks passed!')} The server is running properly.")
            return 0
    
    print(f"\n{red('Server health check failed!')} Please check the server logs for more information.")
    return 1

if __name__ == "__main__":
    sys.exit(main()) 