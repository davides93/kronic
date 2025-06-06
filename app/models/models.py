"""Database models for Kronic application."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class User(Base):
    """User model for authentication and authorization."""
    
    __tablename__ = "users"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    
    # Relationships
    user_roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    roles = relationship("Role", secondary="user_roles", back_populates="users")

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}')>"


class Role(Base):
    """Role model for authorization."""
    
    __tablename__ = "roles"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    permissions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    
    # Relationships
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    users = relationship("User", secondary="user_roles", back_populates="roles")

    def __repr__(self) -> str:
        return f"<Role(id={self.id}, name='{self.name}')>"


class UserRole(Base):
    """Association table for many-to-many relationship between users and roles."""
    
    __tablename__ = "user_roles"
    
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True
    )
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    
    # Relationships
    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="user_roles")
    
    __table_args__ = (
        UniqueConstraint("user_id", "role_id", name="unique_user_role"),
    )

    def __repr__(self) -> str:
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"