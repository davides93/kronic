"""Authentication API endpoints for v1."""

import logging
from flask import Blueprint, request, jsonify, render_template

log = logging.getLogger("app.api.v1.auth")

# Create auth blueprint for v1
auth_v1 = Blueprint('auth_v1', __name__, url_prefix='/api/v1/auth')


@auth_v1.route('/login', methods=['POST'])
def login():
    """Login endpoint with JWT token generation."""
    try:
        # Import auth modules - try both paths for compatibility
        try:
            from auth import UserManager
            from jwt_auth import (
                JWTManager, 
                SecurePasswordManager, 
                BruteForceProtection, 
                SessionManager
            )
        except ImportError:
            from ...auth import UserManager
            from ...jwt_auth import (
                JWTManager, 
                SecurePasswordManager, 
                BruteForceProtection, 
                SessionManager
            )
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request format'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Check brute force protection
        if BruteForceProtection.is_blocked(email):
            return jsonify({'error': 'Account temporarily locked due to too many failed attempts'}), 423
        
        # Authenticate user
        user = UserManager.get_user_by_email(email)
        if not user or not SecurePasswordManager.verify_password(password, user.password_hash):
            BruteForceProtection.record_failed_attempt(email)
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is disabled'}), 401
        
        # Clear failed attempts on successful login
        BruteForceProtection.clear_failed_attempts(email)
        
        # Generate tokens
        tokens = JWTManager.generate_tokens(user.id, user.email)
        
        # Create session
        SessionManager.create_session(user.id, tokens['access_token'])
        
        # Update last login
        UserManager.update_last_login(user.email)
        
        log.info(f"User logged in: {email}")
        
        return jsonify({
            'message': 'Login successful',
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
            'user': {
                'id': str(user.id),
                'email': user.email
            }
        }), 200
    
    except Exception as e:
        log.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@auth_v1.route('/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token using refresh token."""
    try:
        try:
            from jwt_auth import JWTManager, SessionManager
        except ImportError:
            from ...jwt_auth import JWTManager, SessionManager
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request format'}), 400
        
        refresh_token = data.get('refresh_token')
        if not refresh_token:
            return jsonify({'error': 'Refresh token is required'}), 400
        
        # Verify refresh token
        payload = JWTManager.verify_refresh_token(refresh_token)
        if not payload:
            return jsonify({'error': 'Invalid or expired refresh token'}), 401
        
        # Generate new access token
        new_tokens = JWTManager.generate_tokens(payload['user_id'], payload['email'])
        
        # Update session
        SessionManager.update_session(payload['user_id'], new_tokens['access_token'])
        
        return jsonify({
            'access_token': new_tokens['access_token'],
            'refresh_token': new_tokens['refresh_token']
        }), 200
    
    except Exception as e:
        log.error(f"Token refresh error: {e}")
        return jsonify({'error': 'Token refresh failed'}), 500


@auth_v1.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint that invalidates session."""
    try:
        try:
            from jwt_auth import JWTManager, SessionManager
        except ImportError:
            from ...jwt_auth import JWTManager, SessionManager
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization header required'}), 401
        
        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            return jsonify({'error': 'Invalid authorization header format'}), 401
        
        # Verify token
        payload = JWTManager.verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Invalidate session
        SessionManager.invalidate_session(payload['user_id'])
        
        log.info(f"User logged out: {payload['email']}")
        
        return jsonify({'message': 'Logout successful'}), 200
    
    except Exception as e:
        log.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_v1.route('/profile', methods=['GET'])
def get_profile():
    """Get current user profile."""
    try:
        try:
            from jwt_auth import JWTManager
            from auth import UserManager
        except ImportError:
            from ...jwt_auth import JWTManager
            from ...auth import UserManager
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization header required'}), 401
        
        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            return jsonify({'error': 'Invalid authorization header format'}), 401
        
        # Verify token
        payload = JWTManager.verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Get user details
        user = UserManager.get_user_by_email(payload['email'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': {
                'id': str(user.id),
                'email': user.email,
                'is_active': user.is_active,
                'is_verified': user.is_verified,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'created_at': user.created_at.isoformat()
            }
        }), 200
    
    except Exception as e:
        log.error(f"Get profile error: {e}")
        return jsonify({'error': 'Failed to get profile'}), 500