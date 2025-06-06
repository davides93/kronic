"""Main application entry point for Kronic."""

import logging
import uuid
from functools import wraps

from flask import Flask, request, g, jsonify
from flask_httpauth import HTTPBasicAuth
from flask_cors import CORS

# Import core modules
from app.core.config import CORS_ORIGINS, CORS_ALLOW_CREDENTIALS, API_PREFIX
from app.core.security import verify_password

# Import API blueprints
from app.api.v1.router import api_v1
from app.api.v1.auth import auth_v1
from app.api.v1.users import users_v1

log = logging.getLogger("app.main")

def create_app():
    """Create and configure the Flask application."""
    app = Flask("app", static_url_path="", static_folder="../static", template_folder="../templates")
    
    # Configure CORS
    CORS(app, 
         origins=CORS_ORIGINS,
         allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
         supports_credentials=CORS_ALLOW_CREDENTIALS,
         expose_headers=["X-Request-ID"])
    
    # Configure HTTP Basic Auth
    auth = HTTPBasicAuth()
    auth.verify_password(verify_password)
    
    # Initialize rate limiter
    try:
        from jwt_auth import init_limiter
        limiter = init_limiter(app)
    except ImportError:
        # Fallback for compatibility
        try:
            from ..jwt_auth import init_limiter
            limiter = init_limiter(app)
        except ImportError:
            log.warning("Rate limiter initialization failed")
    
    # Middleware for request ID tracking
    @app.before_request
    def before_request():
        # Generate unique request ID
        g.request_id = str(uuid.uuid4())
    
    @app.after_request
    def after_request(response):
        # Add request ID to response headers
        response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
        return response
    
    # Global error handlers
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 Bad Request errors."""
        return jsonify({
            'error': 'Bad Request',
            'message': str(error.description) if hasattr(error, 'description') else 'Invalid request',
            'request_id': getattr(g, 'request_id', None)
        }), 400

    @app.errorhandler(401)
    def unauthorized(error):
        """Handle 401 Unauthorized errors."""
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'request_id': getattr(g, 'request_id', None)
        }), 401

    @app.errorhandler(403)
    def forbidden(error):
        """Handle 403 Forbidden errors."""
        return jsonify({
            'error': 'Forbidden',
            'message': str(error.description) if hasattr(error, 'description') else 'Access denied',
            'request_id': getattr(g, 'request_id', None)
        }), 403

    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found errors."""
        return jsonify({
            'error': 'Not Found',
            'message': str(error.description) if hasattr(error, 'description') else 'Resource not found',
            'request_id': getattr(g, 'request_id', None)
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        """Handle 405 Method Not Allowed errors."""
        return jsonify({
            'error': 'Method Not Allowed',
            'message': 'The method is not allowed for the requested URL',
            'request_id': getattr(g, 'request_id', None)
        }), 405

    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 Internal Server Error."""
        log.error(f"Internal server error: {error}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'request_id': getattr(g, 'request_id', None)
        }), 500

    # Register API blueprints
    app.register_blueprint(api_v1)
    app.register_blueprint(auth_v1)
    app.register_blueprint(users_v1)
    
    # Register existing auth blueprint for backward compatibility
    try:
        from auth_api import auth_bp
        app.register_blueprint(auth_bp)
    except ImportError:
        try:
            from ..auth_api import auth_bp
            app.register_blueprint(auth_bp)
        except ImportError:
            log.warning("Legacy auth blueprint not found")
    
    # Import and register legacy routes for backward compatibility
    try:
        from app_routes import register_legacy_routes
        register_legacy_routes(app, auth)
    except ImportError:
        log.warning("Legacy routes not found - will create compatibility layer")
        # Create a simple compatibility layer
        register_legacy_compatibility(app, auth)
    
    log.info(f"Flask application created with API prefix: {API_PREFIX}")
    return app


def register_legacy_compatibility(app, auth):
    """Register legacy routes for backward compatibility."""
    from app.core.security import auth_required, namespace_filter
    from flask import render_template, redirect, url_for
    
    @app.route("/")
    @app.route("/namespaces/")
    @auth_required
    def index():
        """Legacy index route."""
        from app.core.config import NAMESPACE_ONLY, KRONIC_NAMESPACE
        if NAMESPACE_ONLY:
            return redirect(f"/namespaces/{KRONIC_NAMESPACE}", code=302)
        
        try:
            from kron import get_cronjobs
        except ImportError:
            from ..kron import get_cronjobs
        
        cronjobs = get_cronjobs()
        namespaces = {}
        # Count cronjobs per namespace
        for cronjob in cronjobs:
            namespaces[cronjob["namespace"]] = namespaces.get(cronjob["namespace"], 0) + 1
        
        return render_template("index.html", namespaces=namespaces)
    
    @app.route("/namespaces/<namespace>")
    @namespace_filter
    @auth_required
    def view_namespace(namespace):
        """Legacy namespace view route."""
        try:
            from kron import get_cronjobs, _interpret_cron_schedule
        except ImportError:
            from ..kron import get_cronjobs, _interpret_cron_schedule
        
        cronjobs = get_cronjobs(namespace)
        cronjobs_with_details = []
        
        for cronjob in cronjobs:
            cronjob_detail = cronjob.copy()
            # Add schedule interpretation
            schedule = cronjob.get("spec", {}).get("schedule", "")
            cronjob_detail["schedule_description"] = _interpret_cron_schedule(schedule)
            cronjobs_with_details.append(cronjob_detail)
        
        return render_template("namespace.html", cronjobs=cronjobs_with_details, namespace=namespace)
    
    @app.route("/healthz")
    def healthz():
        """Legacy health check endpoint."""
        return redirect(url_for('api_v1.health_check'))


# Create the app instance
app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)