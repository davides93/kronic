"""Database configuration and management for Kronic application."""

import logging
import os
from typing import Optional

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

from models import Base

log = logging.getLogger("app.database")

# Database configuration from environment variables
DATABASE_URL = os.environ.get("KRONIC_DATABASE_URL")
DATABASE_HOST = os.environ.get("KRONIC_DATABASE_HOST", "localhost")
DATABASE_PORT = os.environ.get("KRONIC_DATABASE_PORT", "5432")
DATABASE_NAME = os.environ.get("KRONIC_DATABASE_NAME", "kronic")
DATABASE_USER = os.environ.get("KRONIC_DATABASE_USER", "kronic")
DATABASE_PASSWORD = os.environ.get("KRONIC_DATABASE_PASSWORD", "")
DATABASE_POOL_SIZE = int(os.environ.get("KRONIC_DATABASE_POOL_SIZE", "20"))
DATABASE_MAX_OVERFLOW = int(os.environ.get("KRONIC_DATABASE_MAX_OVERFLOW", "0"))
DATABASE_POOL_TIMEOUT = int(os.environ.get("KRONIC_DATABASE_POOL_TIMEOUT", "30"))

# Global variables for database connection
engine: Optional[Engine] = None
SessionLocal: Optional[sessionmaker] = None


def get_database_url() -> Optional[str]:
    """Get the database URL from environment variables."""
    database_url = os.environ.get("KRONIC_DATABASE_URL")
    if database_url:
        return database_url
    
    # Only construct URL if explicitly configured (not using defaults)
    database_host = os.environ.get("KRONIC_DATABASE_HOST")
    database_port = os.environ.get("KRONIC_DATABASE_PORT", "5432")
    database_name = os.environ.get("KRONIC_DATABASE_NAME")
    database_user = os.environ.get("KRONIC_DATABASE_USER")
    database_password = os.environ.get("KRONIC_DATABASE_PASSWORD", "")
    
    # Only build URL if at least host, name, and user are explicitly set
    if database_host and database_name and database_user:
        return (
            f"postgresql://{database_user}:{database_password}@"
            f"{database_host}:{database_port}/{database_name}"
        )
    
    return None


def init_database() -> bool:
    """Initialize database connection and session factory.
    
    Returns:
        bool: True if database is successfully initialized, False otherwise.
    """
    global engine, SessionLocal
    
    database_url = get_database_url()
    if not database_url:
        log.info("No database configuration found, database features disabled")
        return False
    
    # Read pool configuration from environment
    pool_size = int(os.environ.get("KRONIC_DATABASE_POOL_SIZE", "20"))
    max_overflow = int(os.environ.get("KRONIC_DATABASE_MAX_OVERFLOW", "0"))
    pool_timeout = int(os.environ.get("KRONIC_DATABASE_POOL_TIMEOUT", "30"))
    
    try:
        # Create engine with connection pooling
        engine = create_engine(
            database_url,
            poolclass=QueuePool,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_pre_ping=True,  # Verify connections before use
            echo=False,  # Set to True for SQL debugging
        )
        
        # Add connection event listeners for logging
        @event.listens_for(engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            log.debug("Database connection established")
        
        @event.listens_for(engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            log.debug("Database connection checked out from pool")
        
        # Test the connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        
        # Create session factory
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        log.info(f"Database initialized successfully: {database_url.split('@')[1] if '@' in database_url else database_url}")
        return True
        
    except Exception as e:
        log.error(f"Failed to initialize database: {e}")
        engine = None
        SessionLocal = None
        return False


def get_session():
    """Get a database session.
    
    Yields:
        Session: SQLAlchemy database session.
    """
    if not SessionLocal:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def check_database_health() -> dict:
    """Check database connectivity and return health status.
    
    Returns:
        dict: Health status information.
    """
    if not engine:
        return {
            "status": "unhealthy",
            "error": "Database not initialized"
        }
    
    try:
        with engine.connect() as conn:
            # Test basic connectivity
            result = conn.execute(text("SELECT 1 as health_check"))
            result.fetchone()
            
            # Get connection pool status
            pool = engine.pool
            pool_status = {
                "size": pool.size(),
                "checked_in": pool.checkedin(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
                "invalid": pool.invalid()
            }
            
            return {
                "status": "healthy",
                "database_url": get_database_url().split('@')[1] if '@' in get_database_url() else get_database_url(),
                "pool": pool_status
            }
            
    except Exception as e:
        log.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy", 
            "error": str(e)
        }


def create_tables():
    """Create all database tables."""
    if not engine:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    try:
        Base.metadata.create_all(bind=engine)
        log.info("Database tables created successfully")
    except Exception as e:
        log.error(f"Failed to create database tables: {e}")
        raise


def is_database_available() -> bool:
    """Check if database is available and initialized.
    
    Returns:
        bool: True if database is available, False otherwise.
    """
    return engine is not None and SessionLocal is not None