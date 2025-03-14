"""
Evrmore Accounts

A pure REST API service for Evrmore blockchain-based authentication.
No frontend components are included - this is a backend API only.
"""

__version__ = "1.0.0"

# Import key components for easier access
from evrmore_accounts.server_security import (
    AdvancedRateLimiter, 
    SecurityHeadersMiddleware,
    RateLimitExceeded,
    SessionManager,
    init_security
)

# These modules were moved from the root directory
from evrmore_accounts.advanced_rate_limiter import (
    AdvancedRateLimiter as ExternalRateLimiter,
    RateLimitExceeded as ExternalRateLimitExceeded,
    init_rate_limiter
)

from evrmore_accounts.security_headers import (
    SecurityHeadersMiddleware as ExternalSecurityHeadersMiddleware,
    init_security_headers
)

from evrmore_accounts.healthcheck import check_server_health 