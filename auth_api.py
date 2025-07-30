"""Authentication API endpoints."""

import logging
from flask import (
    Blueprint,
    request,
    jsonify,
    render_template,
    redirect,
    make_response,
    url_for,
)

from auth import UserManager
from jwt_auth import (
    JWTManager,
    PasswordValidator,
    SecurePasswordManager,
    BruteForceProtection,
    SessionManager,
    jwt_required,
    get_limiter,
    JWT_REFRESH_TOKEN_EXPIRES,
)
from rate_limiting import rate_limit, get_rate_limiter

log = logging.getLogger("app.auth_api")

# Create authentication blueprint
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/login", methods=["POST"])
@rate_limit("auth/login")
def login():
    """Login endpoint with JWT token generation."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request format"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Check for brute force protection
    client_ip = request.remote_addr
    if BruteForceProtection.is_blocked(email) or BruteForceProtection.is_blocked(
        client_ip
    ):
        return (
            jsonify({"error": "Too many failed attempts. Please try again later."}),
            429,
        )

    # Authenticate user
    user = UserManager.authenticate_user(email, password)
    if not user:
        # Record failed attempt
        BruteForceProtection.record_failed_attempt(email)
        BruteForceProtection.record_failed_attempt(client_ip)

        log.warning(f"Failed login attempt for email: {email} from IP: {client_ip}")
        return jsonify({"error": "Invalid credentials"}), 401

    # Check if user is active
    if not user.is_active:
        return jsonify({"error": "Account is deactivated"}), 401

    # Clear failed attempts on successful login
    BruteForceProtection.clear_failed_attempts(email)
    BruteForceProtection.clear_failed_attempts(client_ip)

    # Generate JWT tokens
    tokens = JWTManager.generate_tokens(user.id, user.email)

    # Store session
    session_data = {
        "user_id": str(user.id),
        "email": user.email,
        "login_time": user.last_login.isoformat() if user.last_login else None,
    }
    SessionManager.store_session(str(user.id), session_data, ttl=3600)

    log.info(f"Successful login for user: {email}")

    # Create response with JSON data
    response_data = {
        "message": "Login successful",
        "token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "expires_in": tokens["expires_in"],
        "user": {
            "id": str(user.id),
            "email": user.email,
            "is_verified": user.is_verified,
        },
    }

    response = make_response(jsonify(response_data), 200)

    # Set tokens as HTTP-only cookies for web authentication
    response.set_cookie(
        "access_token",
        tokens["access_token"],
        max_age=int(tokens["expires_in"]),
        httponly=True,
        secure=request.is_secure,  # Use secure flag if HTTPS
        samesite="Lax",
    )

    response.set_cookie(
        "refresh_token",
        tokens["refresh_token"],
        max_age=int(JWT_REFRESH_TOKEN_EXPIRES.total_seconds()),
        httponly=True,
        secure=request.is_secure,  # Use secure flag if HTTPS
        samesite="Lax",
    )

    return response


@auth_bp.route("/register", methods=["POST"])
@rate_limit("auth/register")
def register():
    """User registration endpoint."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request format"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Validate email format
    import re

    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        return jsonify({"error": "Invalid email format"}), 400

    # Validate password strength
    password_check = PasswordValidator.validate_password_strength(password)
    if not password_check["is_valid"]:
        return (
            jsonify(
                {
                    "error": "Password does not meet security requirements",
                    "details": password_check["errors"],
                }
            ),
            400,
        )

    # Hash password with bcrypt
    hashed_password = SecurePasswordManager.hash_password(password)

    # Create user
    user = UserManager.create_user(
        email,
        hashed_password,
        is_active=True,
        is_verified=False,
        password_already_hashed=True,
    )
    if not user:
        return (
            jsonify(
                {"error": "User with this email already exists or registration failed"}
            ),
            409,
        )

    log.info(f"New user registered: {email}")

    return (
        jsonify(
            {
                "message": "User registered successfully",
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "is_verified": user.is_verified,
                },
            }
        ),
        201,
    )


@auth_bp.route("/refresh", methods=["POST"])
@rate_limit("auth/refresh")
def refresh_token():
    """Refresh access token using refresh token."""
    data = request.get_json()

    # Try to get refresh token from request body first, then from cookies
    refresh_token = None
    if data:
        refresh_token = data.get("refresh_token")

    if not refresh_token:
        refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        return jsonify({"error": "Refresh token is required"}), 400

    # Generate new tokens
    new_tokens = JWTManager.refresh_access_token(refresh_token)
    if not new_tokens:
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    # Create response with new tokens
    response_data = {
        "message": "Token refreshed successfully",
        "token": new_tokens["access_token"],
        "refresh_token": new_tokens["refresh_token"],
        "expires_in": new_tokens["expires_in"],
    }

    response = make_response(jsonify(response_data), 200)

    # Update cookies with new tokens
    response.set_cookie(
        "access_token",
        new_tokens["access_token"],
        max_age=int(new_tokens["expires_in"]),
        httponly=True,
        secure=request.is_secure,
        samesite="Lax",
    )

    response.set_cookie(
        "refresh_token",
        new_tokens["refresh_token"],
        max_age=int(JWT_REFRESH_TOKEN_EXPIRES.total_seconds()),
        httponly=True,
        secure=request.is_secure,
        samesite="Lax",
    )

    return response


@auth_bp.route("/logout", methods=["POST"])
@jwt_required
def logout():
    """Logout endpoint that invalidates session."""
    user_id = request.current_user["user_id"]

    # Delete session from Redis
    SessionManager.delete_session(user_id)

    log.info(f"User logged out: {request.current_user['email']}")

    response = make_response(jsonify({"message": "Logged out successfully"}))

    # Clear JWT cookies if they exist
    response.set_cookie("access_token", "", expires=0)
    response.set_cookie("refresh_token", "", expires=0)

    return response, 200


@auth_bp.route("/profile", methods=["GET"])
@jwt_required
def get_profile():
    """Get current user profile."""
    user_email = request.current_user["email"]
    user = UserManager.get_user_by_email(user_email)

    if not user:
        return jsonify({"error": "User not found"}), 404

    return (
        jsonify(
            {
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "is_active": user.is_active,
                    "is_verified": user.is_verified,
                    "created_at": user.created_at.isoformat(),
                    "last_login": (
                        user.last_login.isoformat() if user.last_login else None
                    ),
                }
            }
        ),
        200,
    )


@auth_bp.route("/change-password", methods=["POST"])
@rate_limit("auth/change-password")
@jwt_required
def change_password():
    """Change user password."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request format"}), 400

    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify({"error": "Current and new passwords are required"}), 400

    user_email = request.current_user["email"]
    user = UserManager.get_user_by_email(user_email)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Verify current password
    if not SecurePasswordManager.verify_password(current_password, user.password_hash):
        return jsonify({"error": "Current password is incorrect"}), 401

    # Validate new password strength
    password_check = PasswordValidator.validate_password_strength(new_password)
    if not password_check["is_valid"]:
        return (
            jsonify(
                {
                    "error": "New password does not meet security requirements",
                    "details": password_check["errors"],
                }
            ),
            400,
        )

    # Update password
    new_hashed_password = SecurePasswordManager.hash_password(new_password)
    success = UserManager.update_password(user_email, new_hashed_password)

    if not success:
        return jsonify({"error": "Failed to update password"}), 500

    log.info(f"Password changed for user: {user_email}")

    return jsonify({"message": "Password changed successfully"}), 200


# Web routes for login/register pages
@auth_bp.route("/login-page", methods=["GET"])
def login_page():
    """Render login page."""
    return render_template("login.html")


@auth_bp.route("/check-auth", methods=["GET"])
def check_auth():
    """Check if user is authenticated."""
    # First try Authorization header
    token = request.headers.get("Authorization")
    if token:
        try:
            token = token.split(" ")[1]  # Bearer <token>
            payload = JWTManager.verify_token(token)
            if payload:
                return jsonify({"authenticated": True, "user": payload}), 200
        except:
            pass

    # Then try cookies
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = JWTManager.verify_token(token)
            if payload:
                return jsonify({"authenticated": True, "user": payload}), 200
        except:
            pass

    return jsonify({"authenticated": False}), 401


@auth_bp.route("/rate-limit-status", methods=["GET"])
def rate_limit_status():
    """Get current rate limiting status."""
    rate_limiter = get_rate_limiter()
    if not rate_limiter:
        return (
            jsonify({"enabled": False, "message": "Rate limiting not available"}),
            200,
        )

    try:
        status = rate_limiter.get_rate_limit_status()
        return jsonify(status), 200
    except Exception as e:
        log.error(f"Failed to get rate limit status: {e}")
        return jsonify({"error": "Failed to get rate limit status"}), 500
