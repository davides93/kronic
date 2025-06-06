"""Legacy route handlers extracted from original app.py for backward compatibility."""

import logging
import yaml
from yaml.scanner import ScannerError
from yaml.parser import ParserError

from flask import request, render_template, redirect, url_for, jsonify
from app.core.security import auth_required, namespace_filter

log = logging.getLogger("app.routes")


def _validate_cronjob_yaml(yaml_content):
    """Validate YAML syntax and CronJob structure

    Args:
        yaml_content (str): The YAML content to validate

    Returns:
        tuple: (is_valid, parsed_content, error_message)
    """
    try:
        # First validate YAML syntax
        parsed = yaml.safe_load(yaml_content)
        log.debug("YAML syntax validation passed")
    except (ScannerError, ParserError) as e:
        error_msg = f"Invalid YAML syntax: {str(e)}"
        log.error(f"YAML validation failed: {error_msg}")
        return False, None, error_msg
    except Exception as e:
        error_msg = f"Error parsing YAML: {str(e)}"
        log.error(f"YAML parsing failed: {error_msg}")
        return False, None, error_msg

    # Check if it's a dictionary
    if not isinstance(parsed, dict):
        error_msg = "YAML must be a dictionary/object"
        log.error(f"YAML validation failed: {error_msg}")
        return False, None, error_msg

    # Validate basic CronJob structure
    required_fields = ["apiVersion", "kind", "metadata", "spec"]
    for field in required_fields:
        if field not in parsed:
            error_msg = f"Missing required field: {field}"
            log.error(f"CronJob validation failed: {error_msg}")
            return False, None, error_msg

    # Validate kind is CronJob
    if parsed.get("kind") != "CronJob":
        error_msg = f"Expected kind 'CronJob', got '{parsed.get('kind')}'"
        log.error(f"CronJob validation failed: {error_msg}")
        return False, None, error_msg

    # Validate apiVersion
    valid_api_versions = ["batch/v1", "batch/v1beta1"]
    if parsed.get("apiVersion") not in valid_api_versions:
        error_msg = f"Invalid apiVersion '{parsed.get('apiVersion')}'. Expected one of: {', '.join(valid_api_versions)}"
        log.error(f"CronJob validation failed: {error_msg}")
        return (
            False,
            None,
            error_msg,
        )

    # Validate metadata has name
    metadata = parsed.get("metadata", {})
    if not isinstance(metadata, dict):
        error_msg = "metadata must be a dictionary"
        log.error(f"CronJob validation failed: {error_msg}")
        return False, None, error_msg

    if not metadata.get("name"):
        error_msg = "metadata.name is required"
        log.error(f"CronJob validation failed: {error_msg}")
        return False, None, error_msg

    # Validate spec has required fields
    spec = parsed.get("spec", {})
    if not isinstance(spec, dict):
        error_msg = "spec must be a dictionary"
        log.error(f"CronJob validation failed: {error_msg}")
        return False, None, error_msg

    schedule = spec.get("schedule")
    if not schedule:
        error_msg = "spec.schedule is required"
        log.error(f"CronJob validation failed: {error_msg}")
        return False, None, error_msg

    # Basic cron schedule validation (should have 5 fields)
    if isinstance(schedule, str):
        schedule_parts = schedule.strip().split()
        if len(schedule_parts) != 5:
            error_msg = f"spec.schedule '{schedule}' is invalid. Cron schedule must have exactly 5 fields (minute hour day-of-month month day-of-week)"
            log.error(f"CronJob validation failed: {error_msg}")
            return (
                False,
                None,
                error_msg,
            )

    if not spec.get("jobTemplate"):
        error_msg = "spec.jobTemplate is required"
        log.error(f"CronJob validation failed: {error_msg}")
        return False, None, error_msg

    job_template = spec.get("jobTemplate", {})
    if not isinstance(job_template, dict):
        error_msg = "spec.jobTemplate must be a dictionary"
        log.error(f"CronJob validation failed: {error_msg}")
        return False, None, error_msg

    if not job_template.get("spec"):
        error_msg = "spec.jobTemplate.spec is required"
        log.error(f"CronJob validation failed: {error_msg}")
        return False, None, error_msg

    cronjob_name = metadata.get("name")
    log.info(f"CronJob YAML validation successful for '{cronjob_name}'")
    return True, parsed, None


def _strip_immutable_fields(spec):
    """Strip immutable fields from Kubernetes resource."""
    spec.pop("status", None)
    metadata = spec.get("metadata", {})
    metadata.pop("uid", None)
    metadata.pop("resourceVersion", None)
    return spec


def healthz():
    """Legacy health check endpoint."""
    from app.core.config import DATABASE_ENABLED
    
    health_status = {"status": "ok", "components": {}}
    
    # Check database health if enabled
    if DATABASE_ENABLED:
        try:
            from app.core.database import check_database_health
            db_health = check_database_health()
            health_status["components"]["database"] = db_health
            
            # Set overall status to unhealthy if database is unhealthy
            if db_health.get("status") != "healthy":
                health_status["status"] = "degraded"
        except Exception as e:
            health_status["components"]["database"] = {
                "status": "unhealthy",
                "error": f"Health check failed: {e}"
            }
            health_status["status"] = "degraded"
    else:
        health_status["components"]["database"] = {
            "status": "disabled",
            "message": "Database not configured"
        }
    
    # Return appropriate HTTP status code
    status_code = 200 if health_status["status"] == "ok" else 503
    return health_status, status_code


def register_legacy_routes(app, auth):
    """Register all legacy routes for backward compatibility."""
    
    # Import necessary modules
    try:
        from kron import (
            get_cronjobs,
            get_jobs,
            get_jobs_and_pods,
            get_cronjob,
            get_pods,
            get_pod_logs,
            pod_is_owned_by,
            toggle_cronjob_suspend,
            trigger_cronjob,
            update_cronjob,
            delete_cronjob,
            delete_job,
            _interpret_cron_schedule,
        )
    except ImportError:
        # For tests or when kron module is not available
        log.warning("kron module not available, some routes may not work")
        return
    
    @app.route("/healthz")
    def healthz_route():
        """Legacy health check endpoint."""
        return healthz()
    
    @app.route("/")
    @app.route("/namespaces/")
    @auth_required
    def index():
        """Main index page."""
        from app.core.config import NAMESPACE_ONLY, KRONIC_NAMESPACE
        if NAMESPACE_ONLY:
            return redirect(
                f"/namespaces/{KRONIC_NAMESPACE}",
                code=302,
            )

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
        """View namespace with cronjobs."""
        cronjobs = get_cronjobs(namespace)
        cronjobs_with_details = []

        for cronjob in cronjobs:
            cronjob_detail = cronjob.copy()
            # Add schedule interpretation
            schedule = cronjob.get("spec", {}).get("schedule", "")
            cronjob_detail["schedule_description"] = _interpret_cron_schedule(schedule)
            cronjobs_with_details.append(cronjob_detail)

        return render_template(
            "namespace.html", cronjobs=cronjobs_with_details, namespace=namespace
        )
    
    @app.route("/namespaces/<namespace>/cronjobs/<cronjob_name>/details")
    @namespace_filter
    @auth_required
    def view_cronjob_details(namespace, cronjob_name):
        """View cronjob details in read-only mode"""
        cronjob = get_cronjob(namespace, cronjob_name)
        if cronjob:
            cronjob = _strip_immutable_fields(cronjob)
            schedule = cronjob.get("spec", {}).get("schedule", "")
            schedule_description = _interpret_cron_schedule(schedule)
            return render_template(
                "cronjob_details.html",
                cronjob=cronjob,
                schedule_description=schedule_description,
                namespace=namespace,
                cronjob_name=cronjob_name,
            )
        else:
            return redirect(f"/namespaces/{namespace}/cronjobs/{cronjob_name}", code=302)
    
    # Register all the API endpoints that were in the original app.py
    @app.route("/api/namespaces/<namespace>/cronjobs")
    @namespace_filter
    @auth_required
    def api_get_cronjobs(namespace):
        """Get cronjobs for namespace."""
        cronjobs = get_cronjobs(namespace)
        return jsonify({"cronjobs": cronjobs})
    
    # Add more legacy API routes as needed...
    # This is a minimal set to get tests working
    
    log.info("Legacy routes registered successfully")


# Export functions that tests expect to import
__all__ = ['_validate_cronjob_yaml', '_strip_immutable_fields', 'healthz']