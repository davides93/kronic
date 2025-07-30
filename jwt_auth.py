"""JWT-based authentication system with security features."""

import os
import re
import logging
import jwt
import bcrypt
import redis
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any

from flask import Flask, request, jsonify, session, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

from auth import UserManager
from database import is_database_available

log = logging.getLogger("app.jwt_auth")

# JWT Configuration
JWT_SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY", "your-secret-key-change-in-production"
)
JWT_ALGORITHM = "HS256"  # Using HS256 for simplicity, can upgrade to RS256 later
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# Redis Configuration
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Rate Limiting Configuration
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
LOGIN_ATTEMPTS_LIMIT = "5 per 15 minutes"

# Initialize Redis connection
redis_client = None
try:
    if RATE_LIMIT_ENABLED:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()  # Test connection
        log.info("Redis connection established for session management")
except Exception as e:
    log.warning(
        f"Redis connection failed: {e}. Rate limiting and sessions will use memory."
    )
    redis_client = None

# Initialize rate limiter
limiter = None


def init_limiter(app: Flask):
    """Initialize Flask-Limiter with the app."""
    global limiter
    if RATE_LIMIT_ENABLED:
        try:
            # Import and initialize the enhanced rate limiting system
            from rate_limiting import init_rate_limiter

            rate_limiter = init_rate_limiter(app, redis_client)

            # Keep the old limiter for backward compatibility
            storage_uri = REDIS_URL if redis_client else None
            limiter = Limiter(
                key_func=get_remote_address,
                app=app,
                storage_uri=storage_uri,
                default_limits=["200 per day", "50 per hour"],
            )
            log.info("Rate limiter initialized")
            return rate_limiter
        except Exception as e:
            log.error(f"Failed to initialize rate limiter: {e}")
            limiter = None
    return limiter


def get_limiter():
    """Get the rate limiter instance."""
    return limiter


class PasswordValidator:
    """Password strength validation."""

    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """
        Validate password strength according to security requirements.

        Returns:
            Dict with 'is_valid' boolean and 'errors' list
        """
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")

        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        if not re.search(r"\d", password):
            errors.append("Password must contain at least one number")

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")

        # Check for common weak passwords
        weak_passwords = ["password", "12345678", "qwerty123", "admin123"]
        if password.lower() in weak_passwords:
            errors.append("Password is too common and easily guessable")

        return {"is_valid": len(errors) == 0, "errors": errors}


class SecurePasswordManager:
    """Secure password hashing using bcrypt."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt with salt."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against bcrypt hash."""
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except Exception as e:
            log.error(f"Password verification error: {e}")
            return False


class JWTManager:
    """JWT token management."""

    @staticmethod
    def generate_tokens(user_id: str, email: str) -> Dict[str, str]:
        """Generate access and refresh tokens."""
        now = datetime.now().astimezone()

        # Access token payload
        access_payload = {
            "user_id": str(user_id),
            "email": email,
            "exp": now + JWT_ACCESS_TOKEN_EXPIRES,
            "iat": now,
            "type": "access",
        }

        # Refresh token payload
        refresh_payload = {
            "user_id": str(user_id),
            "email": email,
            "exp": now + JWT_REFRESH_TOKEN_EXPIRES,
            "iat": now,
            "type": "refresh",
        }

        access_token = jwt.encode(
            access_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM
        )
        refresh_token = jwt.encode(
            refresh_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": int(JWT_ACCESS_TOKEN_EXPIRES.total_seconds()),
        }

    @staticmethod
    def verify_token(
        token: str, token_type: str = "access"
    ) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

            # Verify token type
            if payload.get("type") != token_type:
                log.warning(
                    f"Invalid token type. Expected {token_type}, got {payload.get('type')}"
                )
                return None

            return payload
        except jwt.ExpiredSignatureError:
            log.info("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            log.warning(f"Invalid token: {e}")
            return None

    @staticmethod
    def refresh_access_token(refresh_token: str) -> Optional[Dict[str, str]]:
        """Generate new access token from refresh token."""
        payload = JWTManager.verify_token(refresh_token, "refresh")
        if not payload:
            return None

        return JWTManager.generate_tokens(payload["user_id"], payload["email"])


class SessionManager:
    """Manage user sessions with Redis."""

    @staticmethod
    def store_session(
        user_id: str, session_data: Dict[str, Any], ttl: int = 3600
    ) -> bool:
        """Store session data in Redis."""
        if not redis_client:
            return False

        try:
            session_key = f"session:{user_id}"
            redis_client.setex(session_key, ttl, str(session_data))
            return True
        except Exception as e:
            log.error(f"Failed to store session: {e}")
            return False

    @staticmethod
    def get_session(user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data from Redis."""
        if not redis_client:
            return None

        try:
            session_key = f"session:{user_id}"
            data = redis_client.get(session_key)
            return eval(data) if data else None
        except Exception as e:
            log.error(f"Failed to retrieve session: {e}")
            return None

    @staticmethod
    def delete_session(user_id: str) -> bool:
        """Delete session data from Redis."""
        if not redis_client:
            return False

        try:
            session_key = f"session:{user_id}"
            redis_client.delete(session_key)
            return True
        except Exception as e:
            log.error(f"Failed to delete session: {e}")
            return False


class BruteForceProtection:
    """Brute force attack protection."""

    @staticmethod
    def record_failed_attempt(identifier: str) -> None:
        """Record a failed login attempt."""
        if not redis_client:
            return

        try:
            key = f"failed_attempts:{identifier}"
            current = redis_client.get(key)
            if current:
                redis_client.incr(key)
            else:
                redis_client.setex(key, 900, 1)  # 15 minutes TTL
        except Exception as e:
            log.error(f"Failed to record attempt: {e}")

    @staticmethod
    def is_blocked(identifier: str) -> bool:
        """Check if identifier is blocked due to too many failed attempts."""
        if not redis_client:
            return False

        try:
            key = f"failed_attempts:{identifier}"
            attempts = redis_client.get(key)
            return int(attempts or 0) >= 5
        except Exception as e:
            log.error(f"Failed to check blocking status: {e}")
            return False

    @staticmethod
    def clear_failed_attempts(identifier: str) -> None:
        """Clear failed attempts for identifier."""
        if not redis_client:
            return

        try:
            key = f"failed_attempts:{identifier}"
            redis_client.delete(key)
        except Exception as e:
            log.error(f"Failed to clear attempts: {e}")


def jwt_required(f):
    """Decorator to require valid JWT token for route access."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        # Get token from Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header:
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({"error": "Invalid authorization header format"}), 401

        # Get token from cookies as fallback
        if not token:
            token = request.cookies.get("access_token")

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        payload = JWTManager.verify_token(token)
        if not payload:
            return jsonify({"error": "Token is invalid or expired"}), 401

        # Add user info to request context
        request.current_user = {
            "user_id": payload["user_id"],
            "email": payload["email"],
        }

        return f(*args, **kwargs)

    return decorated_function


def optional_jwt(f):
    """Decorator that allows but doesn't require JWT token."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        # Get token from Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header:
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                pass

        # Get token from cookies as fallback
        if not token:
            token = request.cookies.get("access_token")

        request.current_user = None
        if token:
            payload = JWTManager.verify_token(token)
            if payload:
                request.current_user = {
                    "user_id": payload["user_id"],
                    "email": payload["email"],
                }

        return f(*args, **kwargs)

    return decorated_function
