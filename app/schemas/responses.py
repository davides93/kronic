"""Request and response schemas for Kronic API."""

from typing import Dict, Any, Optional, List
from datetime import datetime


class HealthResponse:
    """Schema for health check response."""
    
    def __init__(self, status: str, version: str, database: str, error: Optional[str] = None):
        self.status = status
        self.version = version  
        self.database = database
        self.error = error


class ErrorResponse:
    """Schema for error responses."""
    
    def __init__(self, error: str, message: str, request_id: Optional[str] = None):
        self.error = error
        self.message = message
        self.request_id = request_id


class CronJobResponse:
    """Schema for CronJob responses."""
    
    def __init__(self, cronjob: Dict[str, Any]):
        self.cronjob = cronjob


class CronJobListResponse:
    """Schema for CronJob list responses."""
    
    def __init__(self, cronjobs: List[Dict[str, Any]]):
        self.cronjobs = cronjobs


class LoginRequest:
    """Schema for login request."""
    
    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password


class LoginResponse:
    """Schema for login response."""
    
    def __init__(self, message: str, access_token: str, refresh_token: str, user: Dict[str, Any]):
        self.message = message
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.user = user


class UserResponse:
    """Schema for user information response."""
    
    def __init__(self, user: Dict[str, Any]):
        self.user = user


# Export all schemas
__all__ = [
    'HealthResponse',
    'ErrorResponse', 
    'CronJobResponse',
    'CronJobListResponse',
    'LoginRequest',
    'LoginResponse',
    'UserResponse'
]