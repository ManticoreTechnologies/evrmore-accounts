#!/usr/bin/env python3
import sqlite3
import os

# Define database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'evrmore_accounts.db')

def init_db():
    """Initialize the database with the required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT,
        evrmore_address TEXT UNIQUE NOT NULL,
        email TEXT,
        avatar TEXT,
        bio TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        settings TEXT
    )
    ''')
    
    # Create sessions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_jti TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        device_fingerprint TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create challenges table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS challenges (
        id TEXT PRIMARY KEY,
        evrmore_address TEXT NOT NULL,
        challenge TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT 0
    )
    ''')
    
    # Create TOTP secrets table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS totp_secrets (
        user_id TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        enabled BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create WebAuthn credentials table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        credential_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER DEFAULT 0,
        rp_id TEXT,
        name TEXT,
        enabled BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, credential_id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create recovery codes table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS recovery_codes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used BOOLEAN DEFAULT 0,
        used_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    conn.commit()
    conn.close()
    
    print("Database initialized successfully.")

if __name__ == "__main__":
    # Create database directory if it doesn't exist
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    print(f"Database initialized at: {DB_PATH}") 