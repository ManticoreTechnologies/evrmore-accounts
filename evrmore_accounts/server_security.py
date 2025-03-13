#!/usr/bin/env python3
"""
Evrmore Accounts Server Security Components

This module integrates various security enhancements for the Evrmore Accounts API:
1. Security Headers - Protects against common web vulnerabilities like XSS, clickjacking
2. Rate Limiting - Prevents abuse and DoS attacks
3. Session Management - Tracks and manages active sessions
4. JWT Security Enhancements - Strengthens token security
"""
import os
import time
import uuid
import logging
import hashlib
import ipaddress
from typing import Dict, List, Optional, Any, Set, Union
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, Response, g
from flask_jwt_extended import get_jwt, verify_jwt_in_request
from sqlalchemy import text

# Configure logging
logger = logging.getLogger("evrmore_accounts.security")

class SecurityHeadersMiddleware:
    """Middleware to add security headers to all responses"""
    
    def __init__(self, app: Optional[Flask] = None):
        """Initialize the middleware"""
        self.headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Cache-Control': 'no-store, max-age=0',
            'Pragma': 'no-cache'
        }
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize with a Flask application"""
        app.after_request(self.add_security_headers)
        logger.info("Security headers middleware initialized")
    
    def add_security_headers(self, response: Response) -> Response:
        """Add security headers to response"""
        for header, value in self.headers.items():
            response.headers.setdefault(header, value)
        
        return response

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
        """Initialize the rate limiter"""
        # Store request timestamps by IP
        self.requests: Dict[str, List[float]] = {}
        
        # Default rate limits (requests, seconds)
        self.default_limits = {
            # Changed rate limits to be more strict for testing
            "global": (50, 60),     # 50 requests per minute globally (was 100)
            "auth": (3, 60),        # 3 auth requests per minute (was 5)
            "challenge": (5, 60),   # 5 challenge requests per minute (was 10)
            "user": (15, 60)        # 15 user-related requests per minute (was 30)
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
        
        # Enable test mode for more aggressive rate limiting during tests
        self.test_mode = os.environ.get("TESTING", "").lower() in ("true", "1", "yes")
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize with a Flask application"""
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
            # Skip rate limiting for health checks in production
            if request.path.endswith('/health') and not self.test_mode:
                return None
                
            if self.is_rate_limited(request):
                raise RateLimitExceeded()
        
        # Register global rate limiting
        self._register_global_limit(app)
        
        # Register endpoint-specific rate limits
        self._register_endpoint_limits(app)
        
        # Use application config for rate limits
        global_limit = app.config.get("RATE_LIMIT_GLOBAL", 100)
        auth_limit = app.config.get("RATE_LIMIT_AUTH", 5)
        challenge_limit = app.config.get("RATE_LIMIT_CHALLENGE", 10)
        user_limit = app.config.get("RATE_LIMIT_USER", 30)
        
        # Update rate limits based on app config
        self.default_limits = {
            "global": (global_limit, 60),      # Global limit per minute
            "auth": (auth_limit, 60),         # Auth requests per minute
            "challenge": (challenge_limit, 60),  # Challenge requests per minute
            "user": (user_limit, 60)          # User requests per minute
        }
        
        logger.info(f"Rate limits set: global={global_limit}, auth={auth_limit}, challenge={challenge_limit}, user={user_limit}")
        
        app.extensions["rate_limiter"] = self
        logger.info("Advanced rate limiter initialized")
        
    def add_whitelist(self, ip_or_range: str) -> None:
        """Add IP or range to whitelist"""
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
        """Add IP or range to blacklist"""
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
        """Get the client IP address, handling proxies"""
        # Try X-Forwarded-For first (for proxied requests)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Get the first IP in the chain (client IP)
            return forwarded_for.split(",")[0].strip()
        
        # Fall back to remote_addr
        return request.remote_addr or "0.0.0.0"
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted"""
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
        """Check if an IP is blacklisted"""
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
        """Check if request should be rate limited
        
        Args:
            req: Flask request object
            
        Returns:
            True if the request exceeds rate limits
        """
        ip = self.get_client_ip()
        now = time.time()
        
        # Track request
#!/usr/bin/env python3
"""
Evrmore Accounts Server Security Components

This module integrates various security enhancements for the Evrmore Accounts API:
1. Security Headers - Protects against common web vulnerabilities like XSS, clickjacking
2. Rate Limiting - Prevents abuse and DoS attacks
3. Session Management - Tracks and manages active sessions
4. JWT Security Enhancements - Strengthens token security
"""
import os
import time
import uuid
import logging
import hashlib
import ipaddress
from typing import Dict, List, Optional, Any, Set, Union
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, Response, g
from flask_jwt_extended import get_jwt, verify_jwt_in_request
from sqlalchemy import text

# Configure logging
logger = logging.getLogger("evrmore_accounts.security")

class SecurityHeadersMiddleware:
    """Middleware to add security headers to all responses"""
    
    def __init__(self, app: Optional[Flask] = None):
        """Initialize the middleware"""
        self.headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Cache-Control': 'no-store, max-age=0',
            'Pragma': 'no-cache'
        }
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize with a Flask application"""
        app.after_request(self.add_security_headers)
        logger.info("Security headers middleware initialized")
    
    def add_security_headers(self, response: Response) -> Response:
        """Add security headers to response"""
        for header, value in self.headers.items():
            response.headers.setdefault(header, value)
        
        return response

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
        """Initialize the rate limiter"""
        # Store request timestamps by IP
        self.requests: Dict[str, List[float]] = {}
        
        # Default rate limits (requests, seconds)
        self.default_limits = {
            # Changed rate limits to be more strict for testing
            "global": (50, 60),     # 50 requests per minute globally (was 100)
            "auth": (3, 60),        # 3 auth requests per minute (was 5)
            "challenge": (5, 60),   # 5 challenge requests per minute (was 10)
            "user": (15, 60)        # 15 user-related requests per minute (was 30)
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
        
        # Enable test mode for more aggressive rate limiting during tests
        self.test_mode = os.environ.get("TESTING", "").lower() in ("true", "1", "yes")
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize with a Flask application"""
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
            # Skip rate limiting for health checks in production
            if request.path.endswith('/health') and not self.test_mode:
                return None
                
            if self.is_rate_limited(request):
                raise RateLimitExceeded()
        
        # Register global rate limiting
        self._register_global_limit(app)
        
        # Register endpoint-specific rate limits
        self._register_endpoint_limits(app)
        
        # Use application config for rate limits
        global_limit = app.config.get("RATE_LIMIT_GLOBAL", 100)
        auth_limit = app.config.get("RATE_LIMIT_AUTH", 5)
        challenge_limit = app.config.get("RATE_LIMIT_CHALLENGE", 10)
        user_limit = app.config.get("RATE_LIMIT_USER", 30)
        
        # Update rate limits based on app config
        self.default_limits = {
            "global": (global_limit, 60),      # Global limit per minute
            "auth": (auth_limit, 60),         # Auth requests per minute
            "challenge": (challenge_limit, 60),  # Challenge requests per minute
            "user": (user_limit, 60)          # User requests per minute
        }
        
        logger.info(f"Rate limits set: global={global_limit}, auth={auth_limit}, challenge={challenge_limit}, user={user_limit}")
        
        app.extensions["rate_limiter"] = self
        logger.info("Advanced rate limiter initialized")
        
    def add_whitelist(self, ip_or_range: str) -> None:
        """Add IP or range to whitelist"""
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
        """Add IP or range to blacklist"""
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
        """Get the client IP address, handling proxies"""
        # Try X-Forwarded-For first (for proxied requests)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Get the first IP in the chain (client IP)
            return forwarded_for.split(",")[0].strip()
        
        # Fall back to remote_addr
        return request.remote_addr or "0.0.0.0"
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted"""
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
        """Check if an IP is blacklisted"""
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
        """Check if the current request exceeds rate limits"""
        self.total_requests += 1
        
        # Get client IP
        ip = self.get_client_ip()
        
        # Skip rate limiting for whitelisted IPs, but not in test mode
        if self.is_whitelisted(ip) and not self.test_mode:
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
        """Get rate limiting statistics"""
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "tracked_ips": len(self.requests),
            "whitelisted_ips": len(self.whitelist),
            "blacklisted_ips": len(self.blacklist)
        }

class SessionManager:
    """Tracks and manages active user sessions"""
    
    def __init__(self, db_conn=None):
        """Initialize the session manager"""
        self.db = db_conn
        logger.info("Session manager initialized")
    
    def create_session(self, user_id: str, token_jti: str) -> Dict:
        """Create a new session for a user
        
        Args:
            user_id: User ID
            token_jti: JWT token ID
            
        Returns:
            Session information
        """
        from evrmore_accounts.database import get_db, Session
        
        db = self.db or get_db()
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Get client info
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")[:255]  # Truncate to fit DB field
        
        # Generate device fingerprint
        device_fingerprint = self._create_device_fingerprint()
        
        # Set expiration (match JWT expiration)
        from flask import current_app
        jwt_expire_seconds = current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES", 3600)
        expires_at = datetime.utcnow() + timedelta(seconds=jwt_expire_seconds)
        
        # Create session record
        new_session = Session(
            id=session_id,
            user_id=user_id,
            token_jti=token_jti,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint
        )
        
        db.add(new_session)
        db.commit()
        
        return {
            "session_id": session_id,
            "expires_at": expires_at.isoformat()
        }
    
    def _create_device_fingerprint(self) -> str:
        """Create a fingerprint of the device for session tracking"""
        fingerprint_data = {
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "accept_language": request.headers.get("Accept-Language", ""),
            "accept_encoding": request.headers.get("Accept-Encoding", "")
        }
        
        fingerprint_string = "|".join(f"{k}:{v}" for k, v in fingerprint_data.items())
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    def get_sessions(self, user_id: str) -> List[Dict]:
        """Get all active sessions for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of active sessions
        """
        from evrmore_accounts.database import get_db, Session
        
        db = self.db or get_db()
        sessions = db.query(Session).filter_by(user_id=user_id).all()
        
        return [session.to_dict() for session in sessions]
    
    def update_session_activity(self, token_jti: str) -> bool:
        """Update the last activity time for a session
        
        Args:
            token_jti: JWT token ID
            
        Returns:
            True if session was updated
        """
        from evrmore_accounts.database import get_db, Session
        
        db = self.db or get_db()
        session = db.query(Session).filter_by(token_jti=token_jti).first()
        
        if session:
            session.last_activity = datetime.utcnow()
            db.commit()
            return True
            
        return False
    
    def revoke_session(self, user_id: str, session_id: str) -> bool:
        """Revoke a specific session
        
        Args:
            user_id: User ID
            session_id: Session ID
            
        Returns:
            True if session was revoked
        """
        from evrmore_accounts.database import get_db, Session
        
        db = self.db or get_db()
        session = db.query(Session).filter_by(id=session_id, user_id=user_id).first()
        
        if session:
            db.delete(session)
            db.commit()
            logger.info(f"Session {session_id} revoked for user {user_id}")
            return True
            
        return False
    
    def revoke_all_sessions(self, user_id: str, except_session_id: Optional[str] = None) -> int:
        """Revoke all sessions for a user except the current one
        
        Args:
            user_id: User ID
            except_session_id: Session ID to exclude from revocation
            
        Returns:
            Number of sessions revoked
        """
        from evrmore_accounts.database import get_db, Session
        
        db = self.db or get_db()
        query = db.query(Session).filter_by(user_id=user_id)
        
        if except_session_id:
            query = query.filter(Session.id != except_session_id)
            
        sessions = query.all()
        count = len(sessions)
        
        for session in sessions:
            db.delete(session)
            
        db.commit()
        logger.info(f"Revoked {count} sessions for user {user_id}")
        return count
    
    def is_token_revoked(self, token_jti: str) -> bool:
        """Check if a token has been revoked
        
        This is called by the JWT manager for token verification
        
        Args:
            token_jti: JWT token ID
            
        Returns:
            True if token is revoked
        """
        from evrmore_accounts.database import get_db, Session
        
        # Get database connection
        db = self.db or get_db()
        
        # Check if token exists in sessions table
        session = db.query(Session).filter_by(token_jti=token_jti).first()
        
        # Token is revoked if it doesn't exist in the sessions table
        # or if it has expired
        if not session:
            return True
            
        if session.expires_at < datetime.utcnow():
            # Clean up expired session
            db.delete(session)
            db.commit()
            return True
            
        return False
    
    def clean_expired_sessions(self) -> int:
        """Clean up expired sessions
        
        Returns:
            Number of sessions removed
        """
        from evrmore_accounts.database import get_db, Session
        
        db = self.db or get_db()
        now = datetime.utcnow()
        
        expired_sessions = db.query(Session).filter(Session.expires_at < now).all()
        count = len(expired_sessions)
        
        for session in expired_sessions:
            db.delete(session)
            
        db.commit()
        logger.info(f"Cleaned up {count} expired sessions")
        return count

class EnhancedSecurityLogging:
    """Enhanced security logging for critical events"""
    
    def __init__(self, app=None):
        """Initialize security logging"""
        self.logger = logging.getLogger("evrmore_accounts.security")
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with a Flask application"""
        # Set request ID on each request
        @app.before_request
        def set_request_id():
            g.request_id = str(uuid.uuid4())
            g.request_start_time = time.time()
        
        # Log requests after they complete
        @app.after_request
        def log_request(response):
            # Skip logging for health checks
            if request.path.endswith('/health'):
                return response
                
            # Calculate request duration
            duration_ms = 0
            if hasattr(g, 'request_start_time'):
                duration_ms = int((time.time() - g.request_start_time) * 1000)
            
            # Log the request
            status_code = response.status_code
            log_level = logging.INFO if status_code < 400 else logging.WARNING
            
            # Get user ID if authenticated
            user_id = getattr(g, 'user_id', None)
            
            self.logger.log(
                log_level,
                f"Request: {request.method} {request.path} - {status_code} - {duration_ms}ms - User: {user_id or 'anonymous'} - IP: {request.remote_addr}"
            )
            
            return response
        
        logger.info("Enhanced security logging initialized")
    
    def log_security_event(self, event_type, user_id=None, details=None):
        """Log a security event"""
        event_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": getattr(g, 'request_id', str(uuid.uuid4())),
            "event_type": event_type,
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent', 'Unknown'),
            "user_id": user_id,
            "details": details or {}
        }
        
        self.logger.info(f"Security event: {event_type} - User: {user_id or 'anonymous'} - IP: {request.remote_addr}")
        
        # In a production environment, you'd store this in a security events database
        return event_data
    
    def log_auth_attempt(self, success, user_id=None, evrmore_address=None, error=None):
        """Log an authentication attempt"""
        details = {
            "success": success,
            "evrmore_address": evrmore_address
        }
        
        if error:
            details["error"] = error
        
        event_type = "authentication_success" if success else "authentication_failure"
        return self.log_security_event(event_type, user_id, details)
    
    def log_password_change(self, user_id, success, error=None):
        """Log a password change event"""
        details = {"success": success}
        
        if error:
            details["error"] = error
        
        event_type = "password_change"
        return self.log_security_event(event_type, user_id, details)
    
    def log_2fa_event(self, event_type, user_id, success, method=None, error=None):
        """Log a 2FA-related event"""
        details = {
            "success": success,
            "method": method or "unknown"
        }
        
        if error:
            details["error"] = error
        
        return self.log_security_event(f"2fa_{event_type}", user_id, details)
    
    def log_account_lockout(self, user_id, reason):
        """Log an account lockout event"""
        details = {"reason": reason}
        return self.log_security_event("account_lockout", user_id, details)
    
    def log_suspicious_activity(self, user_id, activity_type, details=None):
        """Log suspicious activity"""
        event_details = details or {}
        event_details["activity_type"] = activity_type
        
        return self.log_security_event("suspicious_activity", user_id, event_details)

def requires_2fa(f):
    """Decorator to ensure 2FA is completed for sensitive operations"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Verify JWT is present
        verify_jwt_in_request()
        
        # Get JWT claims
        claims = get_jwt()
        
        # Check if 2FA is enabled
        if claims.get("requires_2fa", False) and not claims.get("2fa_completed", False):
            return jsonify({
                "error": "two_factor_required",
                "message": "Two-factor authentication is required for this operation",
                "requires_2fa": True
            }), 403
        
        return f(*args, **kwargs)
    return decorated

def init_security(app: Flask) -> Dict[str, Any]:
    """Initialize all security components for a Flask application
    
    Args:
        app: Flask application
        
    Returns:
        Dictionary containing all initialized security components
    """
    # Add security headers
    security_headers = SecurityHeadersMiddleware(app)
    
    # Add rate limiting
    rate_limiter = AdvancedRateLimiter(app)
    
    # Add common whitelists
    rate_limiter.add_whitelist("127.0.0.1")  # localhost
    
    # Add session management
    session_manager = SessionManager()
    
    # Add enhanced logging
    security_logging = EnhancedSecurityLogging(app)
    
    # Return all components
    return {
        "security_headers": security_headers,
        "rate_limiter": rate_limiter,
        "session_manager": session_manager,
        "security_logging": security_logging
    } 