"""Enhanced rate limiting system for Kronic API."""

import logging
import os
from functools import wraps
from typing import Dict, Optional, Any, Tuple
from flask import request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

log = logging.getLogger("app.rate_limiting")

# Rate limit configuration
RATE_LIMITS = {
    "default": "100/hour",
    "auth/login": "5/15minutes", 
    "auth/register": "3/hour",
    "auth/refresh": "10/hour",
    "auth/change-password": "3/hour",
    "api/*": "1000/hour",
    "password-reset": "3/hour"
}

# Rate limiting configuration
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Internal service bypass configuration
INTERNAL_SERVICE_IPS = os.environ.get("INTERNAL_SERVICE_IPS", "").split(",")
INTERNAL_SERVICE_TOKENS = os.environ.get("INTERNAL_SERVICE_TOKENS", "").split(",")


class RateLimitManager:
    """Enhanced rate limiting manager with comprehensive features."""
    
    def __init__(self, app=None, redis_client=None):
        self.app = app
        self.redis_client = redis_client
        self.limiter = None
        
        if app is not None:
            self.init_app(app, redis_client)
    
    def init_app(self, app, redis_client=None):
        """Initialize rate limiter with Flask app."""
        self.app = app
        self.redis_client = redis_client
        
        if not RATE_LIMIT_ENABLED:
            log.info("Rate limiting disabled")
            return
            
        try:
            storage_uri = REDIS_URL if redis_client else None
            self.limiter = Limiter(
                key_func=self._get_rate_limit_key,
                app=app,
                storage_uri=storage_uri,
                default_limits=[RATE_LIMITS["default"]],
                headers_enabled=True,
                on_breach=self._rate_limit_handler
            )
            log.info("Enhanced rate limiter initialized")
        except Exception as e:
            log.error(f"Failed to initialize rate limiter: {e}")
            self.limiter = None
    
    def _get_rate_limit_key(self):
        """Generate rate limit key based on user or IP."""
        # Check for internal service bypass
        if self._is_internal_service():
            return f"internal:{get_remote_address()}"
            
        # Use user-based rate limiting if authenticated
        if hasattr(request, 'current_user') and request.current_user:
            user_id = request.current_user.get('user_id', 'anonymous')
            return f"user:{user_id}"
        
        # Fall back to IP-based rate limiting
        return f"ip:{get_remote_address()}"
    
    def _is_internal_service(self) -> bool:
        """Check if request is from internal service."""
        # Check IP whitelist
        client_ip = get_remote_address()
        if client_ip in INTERNAL_SERVICE_IPS:
            return True
            
        # Check for internal service token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            if token in INTERNAL_SERVICE_TOKENS:
                return True
                
        # Check for special internal header
        if request.headers.get("X-Internal-Service") == "true":
            return True
            
        return False
    
    def _rate_limit_handler(self, e):
        """Custom rate limit exceeded handler."""
        # Add rate limit headers
        response_data = {
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later.",
            "retry_after": getattr(e, 'retry_after', None)
        }
        
        response = jsonify(response_data)
        response.status_code = 429
        
        # Add standard rate limit headers
        if hasattr(e, 'limit'):
            response.headers['X-RateLimit-Limit'] = str(e.limit.amount)
            
        if hasattr(e, 'remaining'):
            response.headers['X-RateLimit-Remaining'] = str(e.remaining)
            
        if hasattr(e, 'reset_at'):
            response.headers['X-RateLimit-Reset'] = str(int(e.reset_at))
            
        if hasattr(e, 'retry_after'):
            response.headers['Retry-After'] = str(e.retry_after)
        
        log.warning(
            f"Rate limit exceeded for {self._get_rate_limit_key()} "
            f"on {request.endpoint or request.path}"
        )
        
        return response
    
    def get_endpoint_limit(self, endpoint: str) -> str:
        """Get rate limit for specific endpoint."""
        # Check for exact match
        if endpoint in RATE_LIMITS:
            return RATE_LIMITS[endpoint]
            
        # Check for wildcard matches
        for pattern, limit in RATE_LIMITS.items():
            if "*" in pattern:
                prefix = pattern.replace("*", "")
                if endpoint.startswith(prefix):
                    return limit
                    
        # Return default
        return RATE_LIMITS["default"]
    
    def limit_endpoint(self, endpoint: str = None, limit: str = None):
        """Decorator for applying rate limits to endpoints."""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not self.limiter or not RATE_LIMIT_ENABLED:
                    return f(*args, **kwargs)
                
                # Check for internal service bypass
                if self._is_internal_service():
                    log.debug(f"Rate limiting bypassed for internal service: {request.endpoint}")
                    return f(*args, **kwargs)
                
                # Determine the endpoint and limit
                current_endpoint = endpoint or request.endpoint or request.path.strip('/')
                current_limit = limit or self.get_endpoint_limit(current_endpoint)
                
                try:
                    # Apply the rate limit by creating a decorated function and calling it
                    @self.limiter.limit(current_limit)
                    def apply_limit():
                        pass
                    apply_limit()
                    
                    # Add rate limit headers to successful response
                    response = f(*args, **kwargs)
                    if hasattr(response, 'headers'):
                        self._add_rate_limit_headers(response, current_limit)
                    return response
                    
                except Exception as e:
                    # Rate limit exceeded - custom handler will be called
                    raise e
                    
            return decorated_function
        return decorator
    
    def _add_rate_limit_headers(self, response, limit: str):
        """Add rate limit headers to response."""
        if not self.limiter:
            return
            
        try:
            # Parse limit to get amount
            parts = limit.split('/')
            if len(parts) >= 2:
                amount = parts[0]
                response.headers['X-RateLimit-Limit'] = amount
                
                # Get remaining count from limiter storage
                key = self._get_rate_limit_key()
                if self.redis_client:
                    remaining = self._get_remaining_requests(key, limit)
                    if remaining is not None:
                        response.headers['X-RateLimit-Remaining'] = str(remaining)
                        
                    # Calculate reset time
                    reset_time = self._get_reset_time(limit)
                    if reset_time:
                        response.headers['X-RateLimit-Reset'] = str(int(reset_time))
                        
        except Exception as e:
            log.warning(f"Failed to add rate limit headers: {e}")
    
    def _get_remaining_requests(self, key: str, limit: str) -> Optional[int]:
        """Get remaining requests for the current window."""
        if not self.redis_client:
            return None
            
        try:
            # This is a simplified implementation
            # In practice, Flask-Limiter handles this internally
            parts = limit.split('/')
            if len(parts) >= 2:
                amount = int(parts[0])
                current_count = self.redis_client.get(f"FLRL_{key}") or 0
                return max(0, amount - int(current_count))
        except Exception as e:
            log.debug(f"Failed to get remaining requests: {e}")
            return None
    
    def _get_reset_time(self, limit: str) -> Optional[float]:
        """Calculate when the rate limit window resets."""
        try:
            parts = limit.split('/')
            if len(parts) >= 2:
                period = parts[1]
                
                if 'minute' in period:
                    minutes = int(''.join(filter(str.isdigit, period)))
                    return (datetime.now() + timedelta(minutes=minutes)).timestamp()
                elif 'hour' in period:
                    hours = int(''.join(filter(str.isdigit, period)))
                    return (datetime.now() + timedelta(hours=hours)).timestamp()
                elif 'day' in period:
                    days = int(''.join(filter(str.isdigit, period)))
                    return (datetime.now() + timedelta(days=days)).timestamp()
                    
        except Exception as e:
            log.debug(f"Failed to calculate reset time: {e}")
            return None
    
    def get_rate_limit_status(self, endpoint: str = None) -> Dict[str, Any]:
        """Get current rate limit status for endpoint."""
        if not self.limiter or not RATE_LIMIT_ENABLED:
            return {"enabled": False}
            
        current_endpoint = endpoint or request.endpoint or request.path.strip('/')
        current_limit = self.get_endpoint_limit(current_endpoint)
        key = self._get_rate_limit_key()
        
        status = {
            "enabled": True,
            "endpoint": current_endpoint,
            "limit": current_limit,
            "key": key,
            "is_internal": self._is_internal_service()
        }
        
        if self.redis_client:
            status["remaining"] = self._get_remaining_requests(key, current_limit)
            status["reset_time"] = self._get_reset_time(current_limit)
            
        return status


# Global rate limit manager instance
rate_limit_manager = None


def init_rate_limiter(app, redis_client=None):
    """Initialize the global rate limit manager."""
    global rate_limit_manager
    rate_limit_manager = RateLimitManager(app, redis_client)
    return rate_limit_manager


def get_rate_limiter():
    """Get the global rate limit manager."""
    return rate_limit_manager


def rate_limit(endpoint: str = None, limit: str = None):
    """Decorator for applying rate limits to endpoints."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if rate_limit_manager and hasattr(rate_limit_manager, 'limit_endpoint'):
                return rate_limit_manager.limit_endpoint(endpoint, limit)(f)(*args, **kwargs)
            return f(*args, **kwargs)
        return decorated_function
    return decorator