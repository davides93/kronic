"""Compatibility module for legacy app.py imports."""

# Import functions from the new structure for backward compatibility
from app_routes import _validate_cronjob_yaml, _strip_immutable_fields, healthz
from app.core.security import verify_password, namespace_filter
from app.main import app

# Export all the functions that tests expect
__all__ = [
    '_validate_cronjob_yaml',
    '_strip_immutable_fields', 
    'healthz',
    'verify_password',
    'namespace_filter',
    'app'
]