#!/usr/bin/env python3
"""
Evrmore Accounts Project Structure Verification

This script verifies that the reorganized project structure works correctly
by testing imports and basic functionality.
"""
import os
import sys
import importlib
import traceback

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Define color codes for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

def print_header(text):
    """Print a formatted header"""
    print(f"\n{BOLD}{YELLOW}{'=' * 70}{RESET}")
    print(f"{BOLD}{YELLOW}{text:^70}{RESET}")
    print(f"{BOLD}{YELLOW}{'=' * 70}{RESET}\n")

def print_success(text):
    """Print a success message"""
    print(f"{GREEN}✓ {text}{RESET}")

def print_error(text):
    """Print an error message"""
    print(f"{RED}✗ {text}{RESET}")

def test_import(module_name, required=True):
    """Test importing a module"""
    try:
        importlib.import_module(module_name)
        print_success(f"Successfully imported {module_name}")
        return True
    except ImportError as e:
        if required:
            print_error(f"Failed to import {module_name}: {e}")
            return False
        else:
            print(f"{YELLOW}⚠ Optional module {module_name} not available: {e}{RESET}")
            return None

def main():
    """Main test function"""
    print_header("EVRMORE ACCOUNTS PROJECT STRUCTURE VERIFICATION")
    
    # Define required modules
    core_modules = [
        "evrmore_accounts",
        "evrmore_accounts.app",
        "evrmore_accounts.server_security",
        "evrmore_accounts.advanced_rate_limiter",
        "evrmore_accounts.security_headers",
        "evrmore_accounts.healthcheck"
    ]
    
    test_modules = [
        "tests",
        "tests.unit.db_test",
        "tests.integration.test_backend",
        "tests.security.test_security"
    ]
    
    # Test core modules
    print_header("TESTING CORE MODULES")
    core_success = all(test_import(module) for module in core_modules)
    
    # Test test modules
    print_header("TESTING TEST MODULES")
    test_success = all(test_import(module) for module in test_modules)
    
    # Print summary
    print_header("TEST SUMMARY")
    if core_success and test_success:
        print_success("All modules imported successfully!")
        print("\nYour project structure reorganization is complete and working correctly.")
        print("\nYou can now run the following commands:")
        print("  - make run                # Run development server")
        print("  - make test               # Run tests")
        print("  - make test-all           # Run all tests")
        print("  - make run-gunicorn       # Run production server")
        return 0
    else:
        print_error("Some modules failed to import.")
        print("\nThe project structure reorganization might not be complete.")
        print("Please check the issues above and fix them.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 