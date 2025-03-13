#!/usr/bin/env python3
"""
Advanced Rate Limiter for Evrmore Accounts

This module provides advanced rate limiting functionality for the API,
with IP-based limiting, endpoint-specific rules, and whitelist/blacklist support.
"""
import time
import logging
from typing import Dict, List, Optional, Callable, Tuple, Any, Union
from functools import wraps
from flask import Flask, request, jsonify, Response
import ipaddress

# Configure logging
logger = logging.getLogger("evrmore_accounts.rate_limiter")

class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded"""
    pass

class AdvancedRateLimiter:
    """Advanced rate limiting for Flask applications
    
    Features:
    - IP-based rate limiting
    - IP range limiting
    - Endpoint-specific limits
    - Method-specific limits
    - Whitelist and blacklist support
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """Initialize the rate limiter
        
        Args:
            app: Flask application instance
        """
        # Store request timestamps by IP
        self.requests: Dict[str, List[float]] = {}
        
        # Default rate limits (requests, seconds)
        self.default_limits = {
            "global": (100, 60),    # 100 requests per minute globally
            "auth": (5, 60),        # 5 auth requests per minute
            "challenge": (10, 60),  # 10 challenge requests per minute
            "user": (30, 60)        # 30 user-related requests per minute
        }
        
        # IP whitelists and blacklists
        self.whitelist: List[Union[str, ipaddress.IPv4Network]] = []
        self.blacklist: List[Union[str, ipaddress.IPv4Network]] = []
        
        # Known proxy networks to skip
        self.proxy_networks = [
            ipaddress.IPv4Network("10.0.0.0/8"),      # RFC 1918 private
            ipaddress.IPv4Network("172.16.0.0/12"),   # RFC 1918 private
            ipaddress.IPv4Network("192.168.0.0/16"),  # RFC 1918 private
            ipaddress.IPv4Network("127.0.0.0/8")      # Loopback
        ]
        
        # Statistics
        self.blocked_requests = 0
        self.total_requests = 0
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize with a Flask application
        
        Args:
            app: Flask application instance
        """
        # Register error handler for rate limit exceeded
        @app.errorhandler(RateLimitExceeded)
        def handle_rate_limit_exceeded(e):
            response = jsonify({
                "error": "Too many requests",
                "message": "Rate limit exceeded. Please try again later."
            })
            response.status_code = 429
            response.headers["Retry-After"] = "60"
            return response
        
        # Register before_request handler
        @app.before_request
        def check_rate_limit():
            if self.is_rate_limited(request):
                raise RateLimitExceeded()
        
        # Register global rate limiting
        self._register_global_limit(app)
        
        # Register endpoint-specific rate limits
        self._register_endpoint_limits(app)
        
        app.extensions["rate_limiter"] = self
        app.logger.info("Advanced rate limiter initialized")
        
    def add_whitelist(self, ip_or_range: str) -> None:
        """Add IP or range to whitelist
        
        Args:
            ip_or_range: IP address or CIDR range
        """
        try:
            # Check if it's a CIDR range
            if "/" in ip_or_range:
                network = ipaddress.IPv4Network(ip_or_range)
                self.whitelist.append(network)
            else:
                self.whitelist.append(ip_or_range)
            logger.info(f"Added {ip_or_range} to whitelist")
        except ValueError:
            logger.error(f"Invalid IP or range format: {ip_or_range}")
            
    def add_blacklist(self, ip_or_range: str) -> None:
        """Add IP or range to blacklist
        
        Args:
            ip_or_range: IP address or CIDR range
        """
        try:
            # Check if it's a CIDR range
            if "/" in ip_or_range:
                network = ipaddress.IPv4Network(ip_or_range)
                self.blacklist.append(network)
            else:
                self.blacklist.append(ip_or_range)
            logger.info(f"Added {ip_or_range} to blacklist")
        except ValueError:
            logger.error(f"Invalid IP or range format: {ip_or_range}")
    
    def get_client_ip(self) -> str:
        """Get the client IP address, handling proxies
        
        Returns:
            Client IP address
        """
        # Try X-Forwarded-For first (for proxied requests)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Get the first IP in the chain (client IP)
            return forwarded_for.split(",")[0].strip()
        
        # Fall back to remote_addr
        return request.remote_addr or "0.0.0.0"
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted
        
        Args:
            ip: IP address to check
            
        Returns:
            True if whitelisted, False otherwise
        """
        if not ip or ip == "0.0.0.0":
            return False
            
        # Check direct IP match
        if ip in self.whitelist:
            return True
            
        # Check IP range match
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            for item in self.whitelist:
                if isinstance(item, ipaddress.IPv4Network) and ip_obj in item:
                    return True
        except ValueError:
            pass
            
        return False
    
    def is_blacklisted(self, ip: str) -> bool:
        """Check if an IP is blacklisted
        
        Args:
            ip: IP address to check
            
        Returns:
            True if blacklisted, False otherwise
        """
        if not ip or ip == "0.0.0.0":
            return False
            
        # Check direct IP match
        if ip in self.blacklist:
            return True
            
        # Check IP range match
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            for item in self.blacklist:
                if isinstance(item, ipaddress.IPv4Network) and ip_obj in item:
                    return True
        except ValueError:
            pass
            
        return False
    
    def is_rate_limited(self, req: request) -> bool:
        """Check if the current request exceeds rate limits
        
        Args:
            req: Flask request object
            
        Returns:
            True if rate limited, False otherwise
        """
        self.total_requests += 1
        
        # Get client IP
        ip = self.get_client_ip()
        
        # Skip rate limiting for whitelisted IPs
        if self.is_whitelisted(ip):
            logger.debug(f"Skipping rate limit for whitelisted IP: {ip}")
            return False
        
        # Always rate limit blacklisted IPs
        if self.is_blacklisted(ip):
            logger.info(f"Rate limiting blacklisted IP: {ip}")
            self.blocked_requests += 1
            return True
        
        # Initialize request tracking for this IP if not exists
        if ip not in self.requests:
            self.requests[ip] = []
        
        # Clean up old request timestamps
        now = time.time()
        self.requests[ip] = [ts for ts in self.requests[ip] if now - ts < 3600]  # Keep last hour
        
        # Add current request timestamp
        self.requests[ip].append(now)
        
        # Get the applicable rate limit based on endpoint
        path = req.path.lower()
        method = req.method.upper()
        
        # Determine which limit to apply
        limit_key = "global"  # Default to global limit
        
        if "/api/auth/" in path:
            limit_key = "auth"
        elif "/api/challenge" in path:
            limit_key = "challenge"
        elif "/api/user" in path:
            limit_key = "user"
        
        # Get the limit values
        max_requests, period = self.default_limits[limit_key]
        
        # Count recent requests within the period
        recent_requests = sum(1 for ts in self.requests[ip] if now - ts < period)
        
        # Check if limit exceeded
        if recent_requests > max_requests:
            logger.warning(f"Rate limit exceeded for {ip}: {recent_requests} requests in {period}s (limit: {max_requests})")
            self.blocked_requests += 1
            return True
        
        return False
    
    def _register_global_limit(self, app: Flask) -> None:
        """Register global rate limit"""
        pass  # Handled by before_request
    
    def _register_endpoint_limits(self, app: Flask) -> None:
        """Register endpoint-specific rate limits"""
        pass  # Handled by before_request
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics
        
        Returns:
            Dictionary of statistics
        """
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "tracked_ips": len(self.requests),
            "whitelisted_ips": len(self.whitelist),
            "blacklisted_ips": len(self.blacklist)
        }

def init_rate_limiter(app: Flask) -> AdvancedRateLimiter:
    """Initialize rate limiter with a Flask application
    
    Args:
        app: Flask application instance
        
    Returns:
        Initialized rate limiter instance
    """
    limiter = AdvancedRateLimiter(app)
    
    # Add built-in whitelists (e.g., local development)
    limiter.add_whitelist("127.0.0.1")
    limiter.add_whitelist("::1")
    
    return limiter

# Example usage:
# from advanced_rate_limiter import init_rate_limiter
# 
# app = Flask(__name__)
# rate_limiter = init_rate_limiter(app)
# 
# # Add custom whitelist/blacklist
# rate_limiter.add_whitelist("192.168.1.0/24")  # Whitelist internal network
# rate_limiter.add_blacklist("1.2.3.4")        # Blacklist specific IP 