"""
TSMCA Authentication System - Clean Version
SMS: Twilio | Email: Resend
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import pyotp
import secrets
import hashlib
import json
from datetime import datetime, timedelta
import sqlite3
import os

# Initialize FastAPI FIRST
app = FastAPI(
    title="TSMCA Authentication Server",
    description="Multi-Channel Authentication System",
    version="2.0.0"
)

# CORS Configuration - Allow all origins
from fastapi.responses import JSONResponse

@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.options("/{rest_of_path:path}")
async def preflight_handler(request: Request, rest_of_path: str):
    response = JSONResponse(content={"message": "OK"})
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, GET, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response
)

security = HTTPBearer()
DB_PATH = "tsmca.db"

# SMS Channel - Twilio
class SMSChannel:
    def __init__(self):
        self.enabled = False
        try:
            from twilio.rest import Client
            sid = os.environ.get('TWILIO_ACCOUNT_SID')
            token = os.environ.get('TWILIO_AUTH_TOKEN')
            self.from_number = os.environ.get('TWILIO_PHONE_NUMBER')
            
            if sid and token and self.from_number:
                self.client = Client(sid, token)
                self.enabled = True
                print("✅ SMS Channel (Twilio) enabled")
            else:
                print("⚠️  SMS disabled - missing Twilio credentials")
        except Exception as e:
            print(f"⚠️  SMS disabled: {e}")
    
    def send_code(self, phone: str, code: str):
        if not self.enabled:
            return False
        try:
            self.client.messages.create(
                body=f"TSMCA Code: {code}\nValid for 60 seconds.",
                from_=self.from_number,
                to=phone
            )
            print(f"✅ SMS sent to {phone}")
            return True
        except Exception as e:
            print(f"❌ SMS failed: {e}")
            return False

# Email Channel - Resend
class EmailChannel:
    def __init__(self):
        self.enabled = False
        try:
            import resend
            key = os.environ.get('RESEND_API_KEY')
            if key:
                resend.api_key = key
                self.client = resend.Emails
                self.from_email = "TSMCA <onboarding@resend.dev>"
                self.enabled = True
                print("✅ Email Channel (Resend) enabled")
            else:
                print("⚠️  Email disabled - missing Resend API key")
        except Exception as e:
            print(f"⚠️  Email disabled: {e}")
    
    def send_code(self, email: str, code: str, username: str):
        if not self.enabled:
            return False
        try:
            self.client.send({
                "from": self.from_email,
                "to": [email],
                "subject": "🔐 TSMCA Verification Code",
                "html": f"""
                <div style="font-family: Arial; max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <div style="background: linear-gradient(135deg, #667eea, #764ba2); padding: 30px; text-align: center; color: white;">
                        <div style="font-size: 48px;">🔐</div>
                        <h1 style="margin: 0;">TSMCA Authentication</h1>
                    </div>
                    <div style="padding: 40px;">
                        <p>Hello <strong>{username}</strong>,</p>
                        <p>Your verification code is:</p>
                        <div style="background: #f8f9fa; border: 3px solid #667eea; border-radius: 8px; padding: 25px; text-align: center; margin: 30px 0;">
                            <div style="font-size: 36px; font-weight: bold; color: #667eea; letter-spacing: 10px; font-family: monospace;">{code}</div>
                        </div>
                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; color: #856404;">
                            <strong>⏰ Expires in 60 seconds</strong>
                        </div>
                        <p style="margin-top: 20px;">If you didn't request this, ignore this email.</p>
                    </div>
                    <div style="background: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; font-size: 12px;">
                        <p>© 2026 TSMCA System</p>
                    </div>
                </div>
                """
            })
            print(f"✅ Email sent to {email}")
            return True
        except Exception as e:
            print(f"❌ Email failed: {e}")
            return False

# Initialize channels
sms_channel = SMSChannel()
email_channel = EmailChannel()

# Database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone_number TEXT,
        shared_secret TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT,
        account_status TEXT DEFAULT 'active',
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS trusted_devices (
        device_id TEXT PRIMARY KEY,
        user_id TEXT,
        device_fingerprint TEXT NOT NULL,
        device_type TEXT,
        trust_level TEXT DEFAULT 'normal',
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_used TEXT,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        session_token TEXT PRIMARY KEY,
        user_id TEXT,
        device_id TEXT,
        ip_address TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS auth_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        device_id TEXT,
        auth_method TEXT,
        status TEXT,
        failure_reason TEXT,
        channels_used TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

# Models
class UserRegistration(BaseModel):
    username: str
    email: str
    password: str
    phone_number: Optional[str] = None

class AuthRequest(BaseModel):
    username: str
    device_id: str
    token: str

class MultiChannelAuthRequest(BaseModel):
    username: str
    device_id: str
    channels: list

class AuthResponse(BaseModel):
    success: bool
    session_token: Optional[str] = None
    expires_at: Optional[str] = None
    message: str
    qr_code_data: Optional[str] = None
    channels_used: Optional[list] = None

# Helper functions
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_auth(user_id: str, ip: str, device_id: str, method: str, status: str, reason: str = None, channels: list = None):
    conn = get_db()
    c = conn.cursor()
    channels_str = ','.join(channels) if channels else None
    c.execute("""INSERT INTO auth_logs (user_id, ip_address, device_id, auth_method, status, failure_reason, channels_used)
        VALUES (?, ?, ?, ?, ?, ?, ?)""", (user_id, ip, device_id, method, status, reason, channels_str))
    conn.commit()
    conn.close()

def is_locked(user_id: str) -> bool:
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT locked_until FROM users WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    if result and result['locked_until']:
        locked_until = datetime.fromisoformat(result['locked_until'])
        if datetime.utcnow() < locked_until:
            return True
        else:
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()
    return False

def increment_failures(user_id: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT failed_attempts FROM users WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    if result:
        failed = result['failed_attempts'] + 1
        if failed >= 5:
            locked = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            c.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE user_id = ?", (failed, locked, user_id))
        else:
            c.execute("UPDATE users SET failed_attempts = ? WHERE user_id = ?", (failed, user_id))
        conn.commit()
    conn.close()

def reset_failures(user_id: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET failed_attempts = 0 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def is_trusted(user_id: str, device_id: str) -> bool:
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT device_id FROM trusted_devices WHERE user_id = ? AND device_id = ?", (user_id, device_id))
    result = c.fetchone()
    conn.close()
    return result is not None

def add_device(user_id: str, device_id: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("""INSERT OR REPLACE INTO trusted_devices (device_id, user_id, device_fingerprint, device_type, last_used)
        VALUES (?, ?, ?, ?, ?)""", (device_id, user_id, device_id, "unknown", datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# API Endpoints
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "TSMCA Authentication Server",
        "version": "2.0.0",
        "features": {
            "sms_verification": sms_channel.enabled,
            "email_verification": email_channel.enabled,
            "totp_authentication": True
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/register", response_model=AuthResponse)
async def register(user: UserRegistration, request: Request):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id FROM users WHERE username = ? OR email = ?", (user.username, user.email))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    user_id = secrets.token_hex(16)
    secret = pyotp.random_base32()
    c.execute("""INSERT INTO users (user_id, username, email, phone_number, shared_secret)
        VALUES (?, ?, ?, ?, ?)""", (user_id, user.username, user.email, user.phone_number, secret))
    conn.commit()
    conn.close()
    
    totp = pyotp.TOTP(secret)
    qr_uri = totp.provisioning_uri(name=user.email, issuer_name="TSMCA Auth")
    log_auth(user_id, request.client.host, "registration", "REGISTRATION", "SUCCESS")
    
    return AuthResponse(
        success=True,
        message="Registration successful! Scan QR code with authenticator app.",
        qr_code_data=qr_uri
    )

@app.post("/api/v1/send-verification")
async def send_verification(req: MultiChannelAuthRequest, request: Request):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (req.username,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    totp = pyotp.TOTP(user['shared_secret'])
    code = totp.now()
    
    used = []
    failed = []
    
    if "sms" in req.channels:
        if user['phone_number']:
            if sms_channel.send_code(user['phone_number'], code):
                used.append("SMS")
            else:
                failed.append("SMS")
        else:
            failed.append("SMS (no phone)")
    
    if "email" in req.channels:
        if email_channel.send_code(user['email'], code, user['username']):
            used.append("Email")
        else:
            failed.append("Email")
    
    if "app" in req.channels:
        used.append("Authenticator App")
    
    if not used:
        raise HTTPException(status_code=500, detail=f"Failed to send code. Errors: {', '.join(failed)}")
    
    log_auth(user['user_id'], request.client.host, req.device_id, "MULTI_CHANNEL", "SENT", channels=used)
    
    return {
        "success": True,
        "message": "Verification code sent",
        "channels_used": used,
        "channels_failed": failed if failed else None,
        "code_valid_for": "60 seconds"
    }

@app.post("/api/v1/authenticate", response_model=AuthResponse)
async def authenticate(auth: AuthRequest, request: Request):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (auth.username,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = user['user_id']
    
    if is_locked(user_id):
        log_auth(user_id, request.client.host, auth.device_id, "TOTP", "FAILURE", "Account locked")
        conn.close()
        raise HTTPException(status_code=403, detail="Account locked. Try again in 15 minutes.")
    
    totp = pyotp.TOTP(user['shared_secret'])
    if not totp.verify(auth.token, valid_window=1):
        increment_failures(user_id)
        log_auth(user_id, request.client.host, auth.device_id, "TOTP", "FAILURE", "Invalid token")
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid token")
    
    reset_failures(user_id)
    if not is_trusted(user_id, auth.device_id):
        add_device(user_id, auth.device_id)
    
    session_token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    
    c.execute("""INSERT INTO sessions (session_token, user_id, device_id, ip_address, expires_at)
        VALUES (?, ?, ?, ?, ?)""", (session_token, user_id, auth.device_id, request.client.host, expires))
    c.execute("UPDATE users SET last_login = ? WHERE user_id = ?", (datetime.utcnow().isoformat(), user_id))
    conn.commit()
    conn.close()
    
    log_auth(user_id, request.client.host, auth.device_id, "TOTP", "SUCCESS")
    
    return AuthResponse(
        success=True,
        session_token=session_token,
        expires_at=expires,
        message="Authentication successful"
    )

@app.get("/api/v1/validate")
async def validate(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT s.*, u.username, u.email, u.phone_number
        FROM sessions s JOIN users u ON s.user_id = u.user_id
        WHERE s.session_token = ?""", (token,))
    session = c.fetchone()
    conn.close()
    
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    
    if datetime.utcnow() > datetime.fromisoformat(session['expires_at']):
        raise HTTPException(status_code=401, detail="Session expired")
    
    return {
        "valid": True,
        "user_id": session['user_id'],
        "username": session['username'],
        "email": session['email'],
        "phone_number": session['phone_number'],
        "expires_at": session['expires_at']
    }

@app.post("/api/v1/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM sessions WHERE session_token = ?", (credentials.credentials,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Logged out"}

@app.get("/api/v1/stats")
async def stats():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = c.fetchone()['total_users']
    c.execute("SELECT COUNT(*) as active_sessions FROM sessions WHERE expires_at > ?", (datetime.utcnow().isoformat(),))
    active_sessions = c.fetchone()['active_sessions']
    c.execute("SELECT COUNT(*) as total_devices FROM trusted_devices")
    total_devices = c.fetchone()['total_devices']
    c.execute("""SELECT COUNT(*) as successful FROM auth_logs 
        WHERE status = 'SUCCESS' AND timestamp > ?""", ((datetime.utcnow() - timedelta(hours=24)).isoformat(),))
    successful_24h = c.fetchone()['successful']
    c.execute("""SELECT COUNT(*) as failed FROM auth_logs 
        WHERE status = 'FAILURE' AND timestamp > ?""", ((datetime.utcnow() - timedelta(hours=24)).isoformat(),))
    failed_24h = c.fetchone()['failed']
    conn.close()
    
    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_devices": total_devices,
        "channels_status": {
            "sms_enabled": sms_channel.enabled,
            "email_enabled": email_channel.enabled
        },
        "last_24h": {
            "successful_authentications": successful_24h,
            "failed_authentications": failed_24h
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print("=" * 60)
    print("TSMCA Authentication Server v2.0")
    print("=" * 60)
    print(f"Port: {port}")
    print(f"SMS: {'✅ Enabled' if sms_channel.enabled else '❌ Disabled'}")
    print(f"Email: {'✅ Enabled' if email_channel.enabled else '❌ Disabled'}")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
