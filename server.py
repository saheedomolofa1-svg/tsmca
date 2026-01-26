"""
TSMCA (Time-Synchronized Multi-Channel Authentication) System
Main Server Application
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
import pyotp
import secrets
import hashlib
import json
from datetime import datetime, timedelta
import sqlite3
import uvicorn
from pathlib import Path

# Initialize FastAPI app
app = FastAPI(
    title="TSMCA Authentication Server",
    description="Time-Synchronized Multi-Channel Authentication System",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Database setup
DB_PATH = "tsmca.db"

def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            shared_secret TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT,
            account_status TEXT DEFAULT 'active',
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)
    
    # Trusted devices table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trusted_devices (
            device_id TEXT PRIMARY KEY,
            user_id TEXT,
            device_fingerprint TEXT NOT NULL,
            device_type TEXT,
            trust_level TEXT DEFAULT 'normal',
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_used TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    
    # Sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_token TEXT PRIMARY KEY,
            user_id TEXT,
            device_id TEXT,
            ip_address TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    
    # Authentication logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            device_id TEXT,
            auth_method TEXT,
            status TEXT,
            failure_reason TEXT
        )
    """)
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

# Pydantic Models
class UserRegistration(BaseModel):
    username: str
    email: EmailStr
    password: str

class AuthRequest(BaseModel):
    username: str
    device_id: str
    token: str

class AuthResponse(BaseModel):
    success: bool
    session_token: Optional[str] = None
    expires_at: Optional[str] = None
    message: str
    qr_code_data: Optional[str] = None

class TokenVerification(BaseModel):
    username: str
    token: str

# Helper Functions
def generate_user_id():
    """Generate unique user ID"""
    return secrets.token_hex(16)

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_auth_event(user_id: str, ip: str, device_id: str, method: str, status: str, reason: str = None):
    """Log authentication event"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO auth_logs (user_id, ip_address, device_id, auth_method, status, failure_reason)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, ip, device_id, method, status, reason))
    conn.commit()
    conn.close()

def check_account_locked(user_id: str) -> bool:
    """Check if account is locked"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT locked_until FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result['locked_until']:
        locked_until = datetime.fromisoformat(result['locked_until'])
        if datetime.utcnow() < locked_until:
            return True
        else:
            # Unlock account
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()
    return False

def increment_failed_attempts(user_id: str):
    """Increment failed login attempts and lock if necessary"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT failed_attempts FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    
    if result:
        failed_attempts = result['failed_attempts'] + 1
        
        if failed_attempts >= 5:
            # Lock account for 15 minutes
            locked_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            cursor.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                         (failed_attempts, locked_until, user_id))
        else:
            cursor.execute("UPDATE users SET failed_attempts = ? WHERE user_id = ?",
                         (failed_attempts, user_id))
        
        conn.commit()
    conn.close()

def reset_failed_attempts(user_id: str):
    """Reset failed login attempts"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET failed_attempts = 0 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def is_device_trusted(user_id: str, device_id: str) -> bool:
    """Check if device is trusted"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT device_id FROM trusted_devices WHERE user_id = ? AND device_id = ?",
                  (user_id, device_id))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def add_trusted_device(user_id: str, device_id: str, device_type: str = "unknown"):
    """Add device to trusted list"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO trusted_devices (device_id, user_id, device_fingerprint, device_type, last_used)
        VALUES (?, ?, ?, ?, ?)
    """, (device_id, user_id, device_id, device_type, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# API Endpoints

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "TSMCA Authentication Server",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/register", response_model=AuthResponse)
async def register_user(user: UserRegistration, request: Request):
    """Register a new user and generate TOTP secret"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if username or email already exists
    cursor.execute("SELECT user_id FROM users WHERE username = ? OR email = ?",
                  (user.username, user.email))
    existing = cursor.fetchone()
    
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Generate user ID and TOTP secret
    user_id = generate_user_id()
    totp_secret = pyotp.random_base32()
    password_hash = hash_password(user.password)
    
    # Store user in database
    cursor.execute("""
        INSERT INTO users (user_id, username, email, shared_secret)
        VALUES (?, ?, ?, ?)
    """, (user_id, user.username, user.email, totp_secret))
    
    conn.commit()
    conn.close()
    
    # Generate QR code data for authenticator apps
    totp = pyotp.TOTP(totp_secret)
    qr_uri = totp.provisioning_uri(name=user.email, issuer_name="TSMCA Auth")
    
    log_auth_event(user_id, request.client.host, "registration", "REGISTRATION", "SUCCESS")
    
    return AuthResponse(
        success=True,
        message="User registered successfully. Scan QR code with authenticator app.",
        qr_code_data=qr_uri
    )

@app.post("/api/v1/authenticate", response_model=AuthResponse)
async def authenticate(auth: AuthRequest, request: Request):
    """Authenticate user with TOTP token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user by username
    cursor.execute("SELECT * FROM users WHERE username = ?", (auth.username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = user['user_id']
    
    # Check if account is locked
    if check_account_locked(user_id):
        log_auth_event(user_id, request.client.host, auth.device_id, "TOTP", "FAILURE", "Account locked")
        conn.close()
        raise HTTPException(status_code=403, detail="Account is locked. Please try again later.")
    
    # Verify TOTP token
    totp = pyotp.TOTP(user['shared_secret'])
    
    if not totp.verify(auth.token, valid_window=1):
        increment_failed_attempts(user_id)
        log_auth_event(user_id, request.client.host, auth.device_id, "TOTP", "FAILURE", "Invalid token")
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    # Reset failed attempts on successful authentication
    reset_failed_attempts(user_id)
    
    # Check device trust level
    device_trusted = is_device_trusted(user_id, auth.device_id)
    
    if not device_trusted:
        # Add new device to trusted list
        add_trusted_device(user_id, auth.device_id)
    
    # Generate session token
    session_token = generate_session_token()
    expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    
    # Store session
    cursor.execute("""
        INSERT INTO sessions (session_token, user_id, device_id, ip_address, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (session_token, user_id, auth.device_id, request.client.host, expires_at))
    
    # Update last login
    cursor.execute("UPDATE users SET last_login = ? WHERE user_id = ?",
                  (datetime.utcnow().isoformat(), user_id))
    
    conn.commit()
    conn.close()
    
    log_auth_event(user_id, request.client.host, auth.device_id, "TOTP", "SUCCESS")
    
    return AuthResponse(
        success=True,
        session_token=session_token,
        expires_at=expires_at,
        message="Authentication successful"
    )

@app.get("/api/v1/validate")
async def validate_session(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate session token"""
    session_token = credentials.credentials
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, u.username, u.email 
        FROM sessions s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.session_token = ?
    """, (session_token,))
    session = cursor.fetchone()
    conn.close()
    
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session token")
    
    # Check expiration
    expires_at = datetime.fromisoformat(session['expires_at'])
    if datetime.utcnow() > expires_at:
        raise HTTPException(status_code=401, detail="Session expired")
    
    return {
        "valid": True,
        "user_id": session['user_id'],
        "username": session['username'],
        "email": session['email'],
        "expires_at": session['expires_at']
    }

@app.post("/api/v1/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logout and invalidate session"""
    session_token = credentials.credentials
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Logged out successfully"}

@app.get("/api/v1/users/{username}/devices")
async def get_user_devices(username: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get trusted devices for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user ID from username
    cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get devices
    cursor.execute("""
        SELECT device_id, device_type, trust_level, first_seen, last_used
        FROM trusted_devices
        WHERE user_id = ?
    """, (user['user_id'],))
    
    devices = cursor.fetchall()
    conn.close()
    
    return {
        "username": username,
        "devices": [dict(device) for device in devices]
    }

@app.post("/api/v1/verify-token")
async def verify_token(verification: TokenVerification):
    """Verify TOTP token without authentication (for testing)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT shared_secret FROM users WHERE username = ?", (verification.username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    totp = pyotp.TOTP(user['shared_secret'])
    is_valid = totp.verify(verification.token, valid_window=1)
    
    return {
        "valid": is_valid,
        "message": "Token is valid" if is_valid else "Token is invalid or expired"
    }

@app.get("/api/v1/stats")
async def get_stats():
    """Get system statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = cursor.fetchone()['total_users']
    
    cursor.execute("SELECT COUNT(*) as active_sessions FROM sessions WHERE expires_at > ?",
                  (datetime.utcnow().isoformat(),))
    active_sessions = cursor.fetchone()['active_sessions']
    
    cursor.execute("SELECT COUNT(*) as total_devices FROM trusted_devices")
    total_devices = cursor.fetchone()['total_devices']
    
    cursor.execute("""
        SELECT COUNT(*) as successful_auths 
        FROM auth_logs 
        WHERE status = 'SUCCESS' AND timestamp > ?
    """, ((datetime.utcnow() - timedelta(hours=24)).isoformat(),))
    successful_auths_24h = cursor.fetchone()['successful_auths']
    
    cursor.execute("""
        SELECT COUNT(*) as failed_auths 
        FROM auth_logs 
        WHERE status = 'FAILURE' AND timestamp > ?
    """, ((datetime.utcnow() - timedelta(hours=24)).isoformat(),))
    failed_auths_24h = cursor.fetchone()['failed_auths']
    
    conn.close()
    
    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_devices": total_devices,
        "last_24h": {
            "successful_authentications": successful_auths_24h,
            "failed_authentications": failed_auths_24h
        }
    }

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    
    print("=" * 60)
    print("TSMCA Authentication Server Starting...")
    print("=" * 60)
    print(f"Server will be available on port: {port}")
    print("API Documentation: /docs")
    print("=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")