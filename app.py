from flask import Flask, request, render_template, redirect, url_for, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash

from functools import wraps
import logging
import yaml
from yaml.scanner import ScannerError
from yaml.parser import ParserError

import config
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

# Import JWT authentication components
from jwt_auth import init_limiter, optional_jwt, jwt_required
from auth_api import auth_bp
from rate_limiting import rate_limit

app = Flask(__name__, static_url_path="", static_folder="static")
auth = HTTPBasicAuth()

# Initialize rate limiter
limiter = init_limiter(app)

# Register authentication blueprint
app.register_blueprint(auth_bp)

# Setup logger for Flask app
log = logging.getLogger("app.flask")


@auth.verify_password
def verify_password(username, password):
    # Check for JWT token first (from cookies or headers)
    from jwt_auth import JWTManager

    token = None
    # Get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
        except IndexError:
            pass

    # Get token from cookies as fallback
    if not token:
        token = request.cookies.get("access_token")

    # If we have a JWT token, verify it
    if token:
        try:
            payload = JWTManager.verify_token(token)
            if payload:
                log.info(
                    f"User authenticated successfully via JWT token: {payload.get('email', 'unknown')}"
                )
                return payload.get("email", "jwt_user")
        except Exception as e:
            log.debug(f"JWT token verification failed: {e}")

    # Try database authentication if available
    if config.DATABASE_ENABLED:
        try:
            from auth import UserManager

            # For compatibility, treat username as email for database lookup
            user = UserManager.authenticate_user(username, password)
            if user:
                log.info(f"User '{username}' authenticated successfully via database")
                return username
        except Exception as e:
            log.error(f"Database authentication failed for user '{username}': {e}")

    # Fall back to environment variable authentication
    if not config.USERS:
        log.debug("Authentication bypassed - no users configured")
        return True
    else:
        if username in config.USERS and check_password_hash(
            config.USERS.get(username), password
        ):
            log.info(
                f"User '{username}' authenticated successfully via environment variables"
            )
            return username
        else:
            log.warning(f"Authentication failed for user '{username}'")
            return False


# A namespace filter decorator
def namespace_filter(func):
    @wraps(func)
    def wrapper(namespace, *args, **kwargs):
        if config.ALLOW_NAMESPACES:
            if namespace in config.ALLOW_NAMESPACES.split(","):
                log.debug(f"Access granted to namespace '{namespace}'")
                return func(namespace, *args, **kwargs)
        else:
            log.debug(
                f"Access granted to namespace '{namespace}' (no namespace restrictions)"
            )
            return func(namespace, *args, **kwargs)

        log.warning(
            f"Access denied to namespace '{namespace}' due to KRONIC_ALLOW_NAMESPACES setting"
        )
        data = {
            "error": f"Request to {namespace} denied due to KRONIC_ALLOW_NAMESPACES setting",
            "namespace": namespace,
        }
        if request.headers.get(
            "content-type", None
        ) == "application/json" or request.base_url.startswith("/api/"):
            return data, 403
        else:
            return render_template("denied.html", data=data)

    return wrapper


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
    spec.pop("status", None)
    metadata = spec.get("metadata", {})
    metadata.pop("uid", None)
    metadata.pop("resourceVersion", None)
    return spec


@app.route("/healthz")
def healthz():
    health_status = {"status": "ok", "components": {}}

    # Check database health if enabled
    if config.DATABASE_ENABLED:
        try:
            from database import check_database_health

            db_health = check_database_health()
            health_status["components"]["database"] = db_health

            # Set overall status to unhealthy if database is unhealthy
            if db_health.get("status") != "healthy":
                health_status["status"] = "degraded"
        except Exception as e:
            health_status["components"]["database"] = {
                "status": "unhealthy",
                "error": f"Health check failed: {e}",
            }
            health_status["status"] = "degraded"
    else:
        health_status["components"]["database"] = {
            "status": "disabled",
            "message": "Database not configured",
        }

    # Return appropriate HTTP status code
    status_code = 200 if health_status["status"] == "ok" else 503
    return health_status, status_code


# Authentication routes
@app.route("/login")
def login_page():
    """Render the login page."""
    return render_template("login.html")


@app.route("/logout")
def logout_page():
    """Handle logout and redirect to login."""
    response = redirect(url_for("login_page"))
    response.set_cookie("access_token", "", expires=0)
    response.set_cookie("refresh_token", "", expires=0)
    return response


# Authentication wrapper that supports both JWT and Basic Auth
def auth_required(f):
    """Authentication decorator that supports both JWT and HTTP Basic Auth."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First try JWT authentication
        from jwt_auth import JWTManager

        token = None
        # Get token from Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                pass

        # Get token from cookies as fallback
        if not token:
            token = request.cookies.get("access_token")

        if token:
            payload = JWTManager.verify_token(token)
            if payload:
                # Add user info to request context for JWT
                request.current_user = {
                    "user_id": payload["user_id"],
                    "email": payload["email"],
                }
                return f(*args, **kwargs)

        # Check if this is an API request
        if (
            request.path.startswith("/api/")
            or request.headers.get("Content-Type") == "application/json"
        ):
            return jsonify({"error": "Authentication required"}), 401

        # For web requests, redirect to login page instead of basic auth
        if not config.USERS and not config.DATABASE_ENABLED:
            # No authentication configured, allow access
            return f(*args, **kwargs)

        # Redirect to login page for web requests
        return redirect(url_for("login_page"))

    return decorated_function


@app.route("/")
@app.route("/namespaces/")
@auth_required
def index():
    if config.NAMESPACE_ONLY:
        return redirect(
            f"/namespaces/{config.KRONIC_NAMESPACE}",
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
    cronjobs = get_cronjobs(namespace)
    cronjobs_with_details = []
    all_pods = get_pods(namespace=namespace)

    for cronjob in cronjobs:
        cronjob_detail = get_cronjob(namespace, cronjob["name"])
        jobs = get_jobs(namespace=namespace, cronjob_name=cronjob["name"])
        for job in jobs:
            job["pods"] = [
                pod for pod in all_pods if pod_is_owned_by(pod, job["metadata"]["name"])
            ]
        cronjob_detail["jobs"] = jobs

        # Add interpreted schedule
        if (
            cronjob_detail
            and "spec" in cronjob_detail
            and "schedule" in cronjob_detail["spec"]
        ):
            timezone = cronjob_detail["spec"].get("timeZone")
            cronjob_detail["interpreted_schedule"] = _interpret_cron_schedule(
                cronjob_detail["spec"]["schedule"], timezone
            )
        else:
            cronjob_detail["interpreted_schedule"] = "Unknown schedule"

        cronjobs_with_details.append(cronjob_detail)

    return render_template(
        "namespace.html", cronjobs=cronjobs_with_details, namespace=namespace
    )


@app.route("/namespaces/<namespace>/cronjobs/<cronjob_name>", methods=["GET", "POST"])
@namespace_filter
@auth_required
def view_cronjob(namespace, cronjob_name):
    validation_error = None

    if request.method == "POST":
        yaml_content = request.form["yaml"]

        # Validate the YAML content
        is_valid, edited_cronjob, error_message = _validate_cronjob_yaml(yaml_content)

        if not is_valid:
            # If validation fails, show the error and return to edit page
            validation_error = error_message
            cronjob = get_cronjob(namespace, cronjob_name)
            if cronjob:
                cronjob = _strip_immutable_fields(cronjob)
            else:
                # Create default CronJob structure if none exists
                cronjob = {
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "metadata": {"name": cronjob_name, "namespace": namespace},
                    "spec": {
                        "schedule": "*/10 * * * *",
                        "jobTemplate": {
                            "spec": {
                                "template": {
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": "example",
                                                "image": "busybox:latest",
                                                "imagePullPolicy": "IfNotPresent",
                                                "command": [
                                                    "/bin/sh",
                                                    "-c",
                                                    "echo hello; date",
                                                ],
                                            }
                                        ],
                                        "restartPolicy": "OnFailure",
                                    }
                                }
                            }
                        },
                    },
                }
            # Return the user's input for editing
            return render_template(
                "cronjob.html",
                cronjob=cronjob,
                yaml=yaml_content,
                validation_error=validation_error,
            )

        # If validation passes, proceed with update
        cronjob = update_cronjob(namespace, edited_cronjob)

        # Check if the update failed (e.g., Kubernetes API error)
        if "error" in cronjob:
            validation_error = f"Kubernetes API error: {cronjob.get('exception', {}).get('message', 'Unknown error')}"
            # Get the original cronjob for fallback
            original_cronjob = get_cronjob(namespace, cronjob_name)
            if original_cronjob:
                original_cronjob = _strip_immutable_fields(original_cronjob)
            else:
                original_cronjob = edited_cronjob
            return render_template(
                "cronjob.html",
                cronjob=original_cronjob,
                yaml=yaml_content,
                validation_error=validation_error,
            )

        # If the name changed, redirect to the new cronjob
        if cronjob["metadata"]["name"] != cronjob_name:
            return redirect(
                f"/namespaces/{namespace}/cronjobs/{cronjob['metadata']['name']}",
                code=302,
            )
    else:
        cronjob = get_cronjob(namespace, cronjob_name)

    if cronjob:
        cronjob = _strip_immutable_fields(cronjob)
    else:
        cronjob = {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": cronjob_name, "namespace": namespace},
            "spec": {
                "schedule": "*/10 * * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "name": "example",
                                        "image": "busybox:latest",
                                        "imagePullPolicy": "IfNotPresent",
                                        "command": [
                                            "/bin/sh",
                                            "-c",
                                            "echo hello; date",
                                        ],
                                    }
                                ],
                                "restartPolicy": "OnFailure",
                            }
                        }
                    }
                },
            },
        }

    cronjob_yaml = yaml.dump(cronjob)
    return render_template(
        "cronjob.html",
        cronjob=cronjob,
        yaml=cronjob_yaml,
        validation_error=validation_error,
    )


@app.route("/namespaces/<namespace>/cronjobs/<cronjob_name>/details")
@namespace_filter
@auth_required
def view_cronjob_details(namespace, cronjob_name):
    """View cronjob details in read-only mode"""
    cronjob = get_cronjob(namespace, cronjob_name)

    if not cronjob:
        # If cronjob doesn't exist, redirect to create page
        return redirect(f"/namespaces/{namespace}/cronjobs/{cronjob_name}")

    cronjob_yaml = yaml.dump(cronjob)
    return render_template(
        "cronjob_details.html",
        cronjob=cronjob,
        yaml=cronjob_yaml,
    )


@app.route("/api/")
@rate_limit("api/*")
@auth_required
def api_index():
    if config.NAMESPACE_ONLY:
        return redirect(
            f"/api/namespaces/{config.KRONIC_NAMESPACE}",
            code=302,
        )
    # Return all cronjobs
    jobs = get_cronjobs()
    return jobs


@app.route("/api/namespaces/<namespace>/cronjobs")
@app.route("/api/namespaces/<namespace>")
@rate_limit("api/*")
@namespace_filter
@auth_required
def api_namespace(namespace):
    cronjobs = get_cronjobs(namespace)
    return cronjobs


@app.route("/api/namespaces/<namespace>/cronjobs/<cronjob_name>")
@rate_limit("api/*")
@namespace_filter
@auth_required
def api_get_cronjob(namespace, cronjob_name):
    cronjob = get_cronjob(namespace, cronjob_name)
    return cronjob


@app.route("/api/namespaces/<namespace>/cronjobs/<cronjob_name>/yaml")
@namespace_filter
@auth_required
def api_get_cronjob_yaml(namespace, cronjob_name):
    """Get cronjob as YAML string for editor"""
    cronjob = get_cronjob(namespace, cronjob_name)
    if not cronjob:
        return {"error": "CronJob not found"}, 404

    # Strip immutable fields for editing
    cronjob = _strip_immutable_fields(cronjob)
    cronjob_yaml = yaml.dump(cronjob)
    return {"yaml": cronjob_yaml}


@app.route(
    "/api/namespaces/<namespace>/cronjobs/<cronjob_name>/clone", methods=["POST"]
)
@namespace_filter
@auth_required
def api_clone_cronjob(namespace, cronjob_name):
    log.info(f"Cloning cronjob '{cronjob_name}' in namespace '{namespace}'")
    cronjob_spec = get_cronjob(namespace, cronjob_name)
    new_name = request.json["name"]
    log.debug(f"Cloning cronjob '{cronjob_name}' to '{new_name}'")
    cronjob_spec["metadata"]["name"] = new_name
    cronjob_spec["spec"]["jobTemplate"]["metadata"]["name"] = new_name
    cronjob_spec = _strip_immutable_fields(cronjob_spec)
    print(cronjob_spec)
    cronjob = update_cronjob(namespace, cronjob_spec)
    if "error" in cronjob:
        log.error(
            f"Failed to clone cronjob '{cronjob_name}' to '{new_name}': {cronjob.get('exception', {}).get('message', 'Unknown error')}"
        )
    else:
        log.info(
            f"Successfully cloned cronjob '{cronjob_name}' to '{new_name}' in namespace '{namespace}'"
        )
    return cronjob


@app.route("/api/namespaces/<namespace>/cronjobs/create", methods=["POST"])
@rate_limit("api/*")
@namespace_filter
@auth_required
def api_create_cronjob(namespace):
    log.info(f"Creating cronjob in namespace '{namespace}'")
    cronjob_spec = request.json["data"]
    cronjob_name = cronjob_spec.get("metadata", {}).get("name", "unknown")
    log.debug(f"Creating cronjob '{cronjob_name}' in namespace '{namespace}'")
    cronjob = update_cronjob(namespace, cronjob_spec)
    if "error" in cronjob:
        log.error(
            f"Failed to create cronjob '{cronjob_name}' in namespace '{namespace}': {cronjob.get('exception', {}).get('message', 'Unknown error')}"
        )
    else:
        log.info(
            f"Successfully created cronjob '{cronjob_name}' in namespace '{namespace}'"
        )
    return cronjob


@app.route(
    "/api/namespaces/<namespace>/cronjobs/<cronjob_name>/delete", methods=["POST"]
)
@rate_limit("api/*")
@namespace_filter
@auth_required
def api_delete_cronjob(namespace, cronjob_name):
    log.info(f"Deleting cronjob '{cronjob_name}' in namespace '{namespace}'")
    deleted = delete_cronjob(namespace, cronjob_name)
    if "error" in deleted:
        log.error(
            f"Failed to delete cronjob '{cronjob_name}' in namespace '{namespace}': {deleted.get('exception', {}).get('message', 'Unknown error')}"
        )
    else:
        log.info(
            f"Successfully deleted cronjob '{cronjob_name}' in namespace '{namespace}'"
        )
    return deleted


@app.route(
    "/api/namespaces/<namespace>/cronjobs/<cronjob_name>/suspend",
    methods=["GET", "POST"],
)
@namespace_filter
@auth_required
def api_toggle_cronjob_suspend(namespace, cronjob_name):
    if request.method == "GET":
        """Return the suspended status of the <cronjob_name>"""
        log.debug(
            f"Getting suspend status for cronjob '{cronjob_name}' in namespace '{namespace}'"
        )
        cronjob = get_cronjob(namespace, cronjob_name)
        return cronjob
    if request.method == "POST":
        """Toggle the suspended status of <cronjob_name>"""
        log.info(
            f"Toggling suspend status for cronjob '{cronjob_name}' in namespace '{namespace}'"
        )
        cronjob = toggle_cronjob_suspend(namespace, cronjob_name)
        if "error" in cronjob:
            log.error(
                f"Failed to toggle suspend for cronjob '{cronjob_name}' in namespace '{namespace}': {cronjob.get('exception', {}).get('message', 'Unknown error')}"
            )
        else:
            suspend_status = cronjob.get("spec", {}).get("suspend", False)
            log.info(
                f"Successfully {'suspended' if suspend_status else 'resumed'} cronjob '{cronjob_name}' in namespace '{namespace}'"
            )
        return cronjob


@app.route(
    "/api/namespaces/<namespace>/cronjobs/<cronjob_name>/trigger", methods=["POST"]
)
@rate_limit("api/*")
@namespace_filter
@auth_required
def api_trigger_cronjob(namespace, cronjob_name):
    """Manually trigger a job from <cronjob_name>"""
    log.info(f"Triggering cronjob '{cronjob_name}' in namespace '{namespace}'")
    cronjob = trigger_cronjob(namespace, cronjob_name)
    status = 200
    if "error" in cronjob:
        status = cronjob["error"]
        log.error(
            f"Failed to trigger cronjob '{cronjob_name}' in namespace '{namespace}': {cronjob.get('exception', {}).get('message', 'Unknown error')}"
        )
    else:
        log.info(
            f"Successfully triggered cronjob '{cronjob_name}' in namespace '{namespace}'"
        )

    return cronjob, status


@app.route("/api/namespaces/<namespace>/cronjobs/<cronjob_name>/getJobs")
@namespace_filter
@auth_required
def api_get_jobs(namespace, cronjob_name):
    jobs = get_jobs_and_pods(namespace, cronjob_name)
    return jobs


@app.route("/api/namespaces/<namespace>/pods")
@namespace_filter
@auth_required
def api_get_pods(namespace):
    pods = get_pods(namespace)
    return pods


@app.route("/api/namespaces/<namespace>/pods/<pod_name>/logs")
@namespace_filter
@auth_required
def api_get_pod_logs(namespace, pod_name):
    logs = get_pod_logs(namespace, pod_name)
    return logs


@app.route("/api/namespaces/<namespace>/jobs/<job_name>/delete", methods=["POST"])
@namespace_filter
@auth_required
def api_delete_job(namespace, job_name):
    log.info(f"Deleting job '{job_name}' in namespace '{namespace}'")
    deleted = delete_job(namespace, job_name)
    if "error" in deleted:
        log.error(
            f"Failed to delete job '{job_name}' in namespace '{namespace}': {deleted.get('exception', {}).get('message', 'Unknown error')}"
        )
    else:
        log.info(f"Successfully deleted job '{job_name}' in namespace '{namespace}'")
    return deleted
