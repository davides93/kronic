"""API v1 router for Kronic application."""

import logging
from flask import Blueprint, jsonify, request
from app.core.security import auth_required, namespace_filter

log = logging.getLogger("app.api.v1.router")

# Create v1 API blueprint
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')


@api_v1.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    try:
        # Check database health if enabled
        from app.core.config import DATABASE_ENABLED
        if DATABASE_ENABLED:
            try:
                from app.core.database import check_database_health
                db_status = check_database_health()
                if 'error' in db_status:
                    return jsonify({
                        'status': 'unhealthy',
                        'version': 'v1',
                        'database': 'unhealthy',
                        'error': db_status['error']
                    }), 503
            except Exception as e:
                return jsonify({
                    'status': 'unhealthy', 
                    'version': 'v1',
                    'database': 'unhealthy',
                    'error': str(e)
                }), 503
        
        return jsonify({
            'status': 'healthy',
            'version': 'v1',
            'database': 'healthy' if DATABASE_ENABLED else 'disabled'
        }), 200
    except Exception as e:
        log.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'version': 'v1',
            'error': str(e)
        }), 503


@api_v1.route('/namespaces/<namespace>/cronjobs', methods=['GET'])
@namespace_filter
@auth_required
def get_cronjobs(namespace):
    """Get all cronjobs in a namespace."""
    try:
        # Import kron functions - try both import paths for compatibility
        try:
            from kron import get_cronjobs as kron_get_cronjobs
        except ImportError:
            from ..kron import get_cronjobs as kron_get_cronjobs
        
        cronjobs = kron_get_cronjobs(namespace)
        return jsonify({'cronjobs': cronjobs}), 200
    except Exception as e:
        log.error(f"Failed to get cronjobs for namespace {namespace}: {e}")
        return jsonify({'error': 'Failed to retrieve cronjobs'}), 500


@api_v1.route('/namespaces/<namespace>/cronjobs/<cronjob_name>', methods=['GET'])
@namespace_filter  
@auth_required
def get_cronjob(namespace, cronjob_name):
    """Get a specific cronjob."""
    try:
        try:
            from kron import get_cronjob as kron_get_cronjob
        except ImportError:
            from ..kron import get_cronjob as kron_get_cronjob
        
        cronjob = kron_get_cronjob(namespace, cronjob_name)
        if not cronjob:
            return jsonify({'error': 'CronJob not found'}), 404
        return jsonify(cronjob), 200
    except Exception as e:
        log.error(f"Failed to get cronjob {cronjob_name} in namespace {namespace}: {e}")
        return jsonify({'error': 'Failed to retrieve cronjob'}), 500


@api_v1.route('/namespaces/<namespace>/cronjobs/<cronjob_name>/suspend', methods=['POST'])
@namespace_filter
@auth_required
def suspend_cronjob(namespace, cronjob_name):
    """Toggle cronjob suspend status."""
    try:
        try:
            from kron import toggle_cronjob_suspend
        except ImportError:
            from ..kron import toggle_cronjob_suspend
        
        result = toggle_cronjob_suspend(namespace, cronjob_name)
        return jsonify(result), 200
    except Exception as e:
        log.error(f"Failed to toggle suspend for cronjob {cronjob_name} in namespace {namespace}: {e}")
        return jsonify({'error': 'Failed to toggle cronjob suspend status'}), 500


@api_v1.route('/namespaces/<namespace>/cronjobs/<cronjob_name>/trigger', methods=['POST'])
@namespace_filter
@auth_required
def trigger_cronjob(namespace, cronjob_name):
    """Trigger a cronjob manually."""
    try:
        try:
            from kron import trigger_cronjob as kron_trigger_cronjob
        except ImportError:
            from ..kron import trigger_cronjob as kron_trigger_cronjob
        
        result = kron_trigger_cronjob(namespace, cronjob_name)
        return jsonify(result), 200
    except Exception as e:
        log.error(f"Failed to trigger cronjob {cronjob_name} in namespace {namespace}: {e}")
        return jsonify({'error': 'Failed to trigger cronjob'}), 500


# Error handlers for this blueprint
@api_v1.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors."""
    return jsonify({
        'error': 'Bad Request',
        'message': str(error.description) if hasattr(error, 'description') else 'Invalid request'
    }), 400


@api_v1.errorhandler(401)
def unauthorized(error):
    """Handle 401 Unauthorized errors."""
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required'
    }), 401


@api_v1.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden errors."""
    return jsonify({
        'error': 'Forbidden',
        'message': str(error.description) if hasattr(error, 'description') else 'Access denied'
    }), 403


@api_v1.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors."""
    return jsonify({
        'error': 'Not Found',
        'message': str(error.description) if hasattr(error, 'description') else 'Resource not found'
    }), 404


@api_v1.errorhandler(500)
def internal_server_error(error):
    """Handle 500 Internal Server Error."""
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred'
    }), 500