"""User management and authentication for Kronic application."""

import logging
import uuid
from datetime import datetime
from typing import Optional, List

from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt

from database import get_session, is_database_available
from models import User, Role, UserRole

log = logging.getLogger("app.auth")


class UserManager:
    """Manages user operations."""

    @staticmethod
    def create_user(
        email: str,
        password: str,
        is_active: bool = True,
        is_verified: bool = False,
        password_already_hashed: bool = False,
    ) -> Optional[User]:
        """Create a new user.

        Args:
            email: User email address
            password: Plain text password or already hashed password
            is_active: Whether user is active
            is_verified: Whether user is verified
            password_already_hashed: If True, password is already hashed with bcrypt

        Returns:
            User object if created successfully, None otherwise
        """
        if not is_database_available():
            log.warning("Database not available, cannot create user")
            return None

        try:
            session_gen = get_session()
            session = next(session_gen)

            # Check if user already exists
            existing_user = session.query(User).filter(User.email == email).first()
            if existing_user:
                log.warning(f"User with email {email} already exists")
                return None

            # Hash password if not already hashed
            if password_already_hashed:
                password_hash = password
            else:
                # Use bcrypt for new passwords
                salt = bcrypt.gensalt()
                password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode(
                    "utf-8"
                )

            # Create new user
            user = User(
                id=uuid.uuid4(),
                email=email,
                password_hash=password_hash,
                is_active=is_active,
                is_verified=is_verified,
            )

            session.add(user)
            session.commit()
            session.refresh(user)

            log.info(f"User created successfully: {email}")
            return user

        except Exception as e:
            log.error(f"Failed to create user {email}: {e}")
            session.rollback()
            return None
        finally:
            session.close()

    @staticmethod
    def authenticate_user(email: str, password: str) -> Optional[User]:
        """Authenticate a user with email and password.

        Args:
            email: User email address
            password: Plain text password

        Returns:
            User object if authentication successful, None otherwise
        """
        if not is_database_available():
            return None

        try:
            session_gen = get_session()
            session = next(session_gen)

            user = (
                session.query(User)
                .filter(User.email == email, User.is_active == True)
                .first()
            )

            if user:
                # Try bcrypt first (new format), then fallback to werkzeug (old format)
                password_valid = False
                try:
                    # Check if it's a bcrypt hash
                    if user.password_hash.startswith("$2b$"):
                        password_valid = bcrypt.checkpw(
                            password.encode("utf-8"), user.password_hash.encode("utf-8")
                        )
                    else:
                        # Fallback to werkzeug for backward compatibility
                        password_valid = check_password_hash(
                            user.password_hash, password
                        )
                except Exception as e:
                    log.error(f"Password verification error for user {email}: {e}")
                    password_valid = False

                if password_valid:
                    # Update last login
                    user.last_login = datetime.now().astimezone()
                    session.commit()

                    # Access all attributes while session is still active to avoid DetachedInstanceError
                    user_id = user.id
                    user_email = user.email
                    user_is_active = user.is_active
                    user_is_verified = user.is_verified
                    user_last_login = user.last_login

                    # Expunge the user from session before closing
                    session.expunge(user)

                    log.info(f"User authenticated successfully: {email}")
                    return user

            log.warning(f"Authentication failed for user: {email}")
            return None

        except Exception as e:
            log.error(f"Authentication error for user {email}: {e}")
            return None
        finally:
            session.close()

    @staticmethod
    def get_user_by_email(email: str) -> Optional[User]:
        """Get user by email address.

        Args:
            email: User email address

        Returns:
            User object if found, None otherwise
        """
        if not is_database_available():
            return None

        try:
            session_gen = get_session()
            session = next(session_gen)

            user = session.query(User).filter(User.email == email).first()
            return user

        except Exception as e:
            log.error(f"Error retrieving user {email}: {e}")
            return None
        finally:
            session.close()

    @staticmethod
    def get_user_roles(user_id: uuid.UUID) -> List[Role]:
        """Get all roles for a user.

        Args:
            user_id: User ID

        Returns:
            List of Role objects
        """
        if not is_database_available():
            return []

        try:
            session_gen = get_session()
            session = next(session_gen)

            user = session.query(User).filter(User.id == user_id).first()
            if user:
                return user.roles
            return []

        except Exception as e:
            log.error(f"Error retrieving roles for user {user_id}: {e}")
            return []
        finally:
            session.close()

    @staticmethod
    def update_password(email: str, new_password_hash: str) -> bool:
        """Update user password.

        Args:
            email: User email address
            new_password_hash: New hashed password (already hashed with bcrypt)

        Returns:
            True if password updated successfully, False otherwise
        """
        if not is_database_available():
            return False

        try:
            session_gen = get_session()
            session = next(session_gen)

            user = session.query(User).filter(User.email == email).first()
            if user:
                user.password_hash = new_password_hash
                session.commit()
                log.info(f"Password updated for user: {email}")
                return True
            else:
                log.warning(f"User not found for password update: {email}")
                return False

        except Exception as e:
            log.error(f"Error updating password for user {email}: {e}")
            session.rollback()
            return False
        finally:
            session.close()


class RoleManager:
    """Manages role operations."""

    @staticmethod
    def create_role(name: str, permissions: dict = None) -> Optional[Role]:
        """Create a new role.

        Args:
            name: Role name
            permissions: Dictionary of permissions

        Returns:
            Role object if created successfully, None otherwise
        """
        if not is_database_available():
            log.warning("Database not available, cannot create role")
            return None

        if permissions is None:
            permissions = {}

        try:
            session_gen = get_session()
            session = next(session_gen)

            # Check if role already exists
            existing_role = session.query(Role).filter(Role.name == name).first()
            if existing_role:
                log.warning(f"Role with name {name} already exists")
                return None

            # Create new role
            role = Role(name=name, permissions=permissions)

            session.add(role)
            session.commit()
            session.refresh(role)

            log.info(f"Role created successfully: {name}")
            return role

        except Exception as e:
            log.error(f"Failed to create role {name}: {e}")
            session.rollback()
            return None
        finally:
            session.close()

    @staticmethod
    def assign_role_to_user(user_id: uuid.UUID, role_id: int) -> bool:
        """Assign a role to a user.

        Args:
            user_id: User ID
            role_id: Role ID

        Returns:
            True if assignment successful, False otherwise
        """
        if not is_database_available():
            return False

        try:
            session_gen = get_session()
            session = next(session_gen)

            # Check if assignment already exists
            existing_assignment = (
                session.query(UserRole)
                .filter(UserRole.user_id == user_id, UserRole.role_id == role_id)
                .first()
            )

            if existing_assignment:
                log.info(f"User {user_id} already has role {role_id}")
                return True

            # Create new assignment
            user_role = UserRole(user_id=user_id, role_id=role_id)
            session.add(user_role)
            session.commit()

            log.info(f"Role {role_id} assigned to user {user_id}")
            return True

        except Exception as e:
            log.error(f"Failed to assign role {role_id} to user {user_id}: {e}")
            session.rollback()
            return False
        finally:
            session.close()

    @staticmethod
    def get_role_by_name(name: str) -> Optional[Role]:
        """Get role by name.

        Args:
            name: Role name

        Returns:
            Role object if found, None otherwise
        """
        if not is_database_available():
            return None

        try:
            session_gen = get_session()
            session = next(session_gen)

            role = session.query(Role).filter(Role.name == name).first()
            return role

        except Exception as e:
            log.error(f"Error retrieving role {name}: {e}")
            return None
        finally:
            session.close()
