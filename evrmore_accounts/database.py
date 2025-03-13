#!/usr/bin/env python3
"""
Evrmore Accounts Database Module

This module provides SQLAlchemy ORM models and database connectivity
for the Evrmore Accounts application.
"""
import os
import uuid
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy import create_engine, Column, String, Boolean, Integer, ForeignKey, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, scoped_session
from flask import g, current_app

# Configure logging
logger = logging.getLogger("evrmore_accounts.database")

# Define base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Define database path
DB_PATH = os.path.join(BASE_DIR, 'evrmore_accounts', 'data', 'evrmore_accounts.db')

# Create engine - Removed deprecated 'convert_unicode' parameter
engine = create_engine(f'sqlite:///{DB_PATH}')

# Create session factory
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

# Declarative base
Base = declarative_base()
Base.query = db_session.query_property()

class User(Base):
    """User model for Evrmore Accounts"""
    
    __tablename__ = 'users'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), nullable=True)
    evrmore_address = Column(String(64), unique=True, nullable=False)
    email = Column(String(120), nullable=True)
    avatar = Column(String(255), nullable=True)
    bio = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    settings = Column(Text, nullable=True)
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    totp = relationship("TOTPSecret", uselist=False, back_populates="user", cascade="all, delete-orphan")
    webauthn_credentials = relationship("WebAuthnCredential", back_populates="user", cascade="all, delete-orphan")
    recovery_codes = relationship("RecoveryCode", back_populates="user", cascade="all, delete-orphan")
    
    @property
    def two_fa_enabled(self) -> bool:
        """Check if user has 2FA enabled"""
        if self.totp and self.totp.enabled:
            return True
        
        for credential in self.webauthn_credentials:
            if credential.enabled:
                return True
        
        return False
    
    @property
    def settings_dict(self) -> Dict:
        """Return settings as dictionary"""
        if not self.settings:
            return {}
        
        try:
            return json.loads(self.settings)
        except:
            return {}
    
    @settings_dict.setter
    def settings_dict(self, value: Dict):
        """Set settings as JSON string"""
        self.settings = json.dumps(value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary for API responses"""
        return {
            'id': self.id,
            'username': self.username,
            'evrmore_address': self.evrmore_address,
            'email': self.email,
            'avatar': self.avatar,
            'bio': self.bio,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'two_fa_enabled': self.two_fa_enabled
        }

class Session(Base):
    """Session model for tracking active user sessions"""
    
    __tablename__ = 'sessions'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    token_jti = Column(String(36), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    device_fingerprint = Column(String(64), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for API responses"""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }

class Challenge(Base):
    """Challenge model for authentication challenges"""
    
    __tablename__ = 'challenges'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evrmore_address = Column(String(64), nullable=False)
    challenge = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)

class TOTPSecret(Base):
    """TOTP (Time-based One-Time Password) secrets for two-factor authentication"""
    
    __tablename__ = 'totp_secrets'
    
    user_id = Column(String(36), ForeignKey('users.id'), primary_key=True)
    secret = Column(String(32), nullable=False)
    enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="totp")

class WebAuthnCredential(Base):
    """WebAuthn (FIDO2) credentials for two-factor authentication"""
    
    __tablename__ = 'webauthn_credentials'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    credential_id = Column(String(255), nullable=False)
    public_key = Column(Text, nullable=False)
    sign_count = Column(Integer, default=0)
    rp_id = Column(String(255), nullable=True)
    name = Column(String(64), nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="webauthn_credentials")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert credential to dictionary for API responses"""
        return {
            'id': self.id,
            'credential_id': self.credential_id,
            'name': self.name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'enabled': self.enabled
        }

class RecoveryCode(Base):
    """Recovery codes for two-factor authentication"""
    
    __tablename__ = 'recovery_codes'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    code = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="recovery_codes")

def init_db():
    """Initialize the database and create tables"""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized")

def get_db():
    """Get the current database session
    
    Returns:
        SQLAlchemy session
    """
    if 'db' not in g:
        g.db = db_session
    
    return g.db

def close_db(e=None):
    """Close the database session"""
    db = g.pop('db', None)
    
    if db is not None:
        db.close()

def init_app(app):
    """Initialize database with Flask app
    
    Args:
        app: Flask application
    """
    # Register close_db to run when app context ends
    app.teardown_appcontext(close_db)
    
    # Create tables if they don't exist
    with app.app_context():
        init_db()

def get_or_create_user(evrmore_address: str) -> User:
    """Get or create a user by Evrmore address
    
    Args:
        evrmore_address: Evrmore address
        
    Returns:
        User object
    """
    db = get_db()
    user = db.query(User).filter_by(evrmore_address=evrmore_address).first()
    
    if not user:
        user = User(
            evrmore_address=evrmore_address,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(user)
        db.commit()
    
    return user 