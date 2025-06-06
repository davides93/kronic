"""Users API endpoints for v1."""

import logging
from flask import Blueprint, request, jsonify

log = logging.getLogger("app.api.v1.users")

# Create users blueprint for v1
users_v1 = Blueprint('users_v1', __name__, url_prefix='/api/v1/users')


@users_v1.route('/register', methods=['POST'])
def register():
    """User registration endpoint."""
    try:
        # Import auth modules - try both paths for compatibility
        try:
            from auth import UserManager
            from jwt_auth import PasswordValidator, SecurePasswordManager
        except ImportError:
            from ....auth import UserManager
            from ....jwt_auth import PasswordValidator, SecurePasswordManager
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request format'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Validate email format
        if '@' not in email or '.' not in email.split('@')[1]:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if user already exists
        if UserManager.get_user_by_email(email):
            return jsonify({'error': 'User already exists'}), 409
        
        # Validate password strength
        password_check = PasswordValidator.validate_password_strength(password)
        if not password_check['is_valid']:
            return jsonify({
                'error': 'Password does not meet security requirements',
                'details': password_check['errors']
            }), 400
        
        # Hash password and create user
        password_hash = SecurePasswordManager.hash_password(password)
        user = UserManager.create_user(email, password_hash)
        
        if not user:
            return jsonify({'error': 'Failed to create user'}), 500
        
        log.info(f"New user registered: {email}")
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'created_at': user.created_at.isoformat()
            }
        }), 201
    
    except Exception as e:
        log.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


@users_v1.route('/change-password', methods=['POST'])
def change_password():
    """Change user password."""
    try:
        try:
            from auth import UserManager
            from jwt_auth import JWTManager, PasswordValidator, SecurePasswordManager
        except ImportError:
            from ....auth import UserManager
            from ....jwt_auth import JWTManager, PasswordValidator, SecurePasswordManager
        
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
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request format'}), 400
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new passwords are required'}), 400
        
        user_email = payload['email']
        user = UserManager.get_user_by_email(user_email)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Verify current password
        if not SecurePasswordManager.verify_password(current_password, user.password_hash):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password strength
        password_check = PasswordValidator.validate_password_strength(new_password)
        if not password_check['is_valid']:
            return jsonify({
                'error': 'New password does not meet security requirements',
                'details': password_check['errors']
            }), 400
        
        # Update password
        new_hashed_password = SecurePasswordManager.hash_password(new_password)
        success = UserManager.update_password(user_email, new_hashed_password)
        
        if not success:
            return jsonify({'error': 'Failed to update password'}), 500
        
        log.info(f"Password changed for user: {user_email}")
        
        return jsonify({'message': 'Password changed successfully'}), 200
    
    except Exception as e:
        log.error(f"Change password error: {e}")
        return jsonify({'error': 'Failed to change password'}), 500


@users_v1.route('/me', methods=['GET'])
def get_current_user():
    """Get current user information."""
    try:
        try:
            from auth import UserManager
            from jwt_auth import JWTManager
        except ImportError:
            from ....auth import UserManager
            from ....jwt_auth import JWTManager
        
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
        log.error(f"Get current user error: {e}")
        return jsonify({'error': 'Failed to get user information'}), 500