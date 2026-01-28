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
import uvicorn
import os

# Twilio for SMS
from twilio.rest import Client as TwilioClient

# SendGrid for Email
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Initialize FastAPI app
app = FastAPI(
    title="TSMCA Authentication Server",
    description="Time-Synchronized Multi-Channel Authentication with SMS/Email",
    version="2.0.0"
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

# SMS Channel Implementation
class SMSChannel:
    def init(self):
        self.account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
        self.auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
        self.from_number = os.environ.get('TWILIO_PHONE_NUMBER')
        
        if self.account_sid and self.auth_token and self.from_number:
            try:
                self.client = TwilioClient(self.account_sid, self.auth_token)
                self.enabled = True
                print("✅ SMS Channel initialized successfully")
            except Exception as e:
                self.client = None
                self.enabled = False
                print(f"❌ SMS Channel initialization failed: {e}")
        else:
            self.client = None
            self.enabled = False
            print("⚠️  SMS Channel not configured (missing environment variables)")
    
    def send_verification_code(self, phone_number: str, code: str):
        """Send OTP via SMS"""
        if not self.enabled:
            print("⚠️  SMS service not available")
            return False
            
        try:
            message = self.client.messages.create(
                body=f"Your TSMCA verification code is: {code}\n\nValid for 60 seconds. Do not share this code with anyone.",
                from_=self.from_number,
                to=phone_number
            )
            print(f"✅ SMS sent successfully to {phone_number}: {message.sid}")
            return True
        except Exception as e:
            print(f"❌ SMS delivery failed to {phone_number}: {str(e)}")
            return False

# Email Channel Implementation
# Resend for Email (Simpler alternative to SendGrid)
try:
    import resend
    RESEND_AVAILABLE = True
except:
    RESEND_AVAILABLE = False

class EmailChannel:
    def init(self):
        self.api_key = os.environ.get('RESEND_API_KEY')
        self.from_email = os.environ.get('EMAIL_FROM', 'onboarding@resend.dev')
        
        if self.api_key and RESEND_AVAILABLE:
            try:
                resend.api_key = self.api_key
                self.enabled = True
                print("✅ Email Channel (Resend) initialized successfully")
            except Exception as e:
                self.enabled = False
                print(f"❌ Email Channel initialization failed: {e}")
        else:
            self.enabled = False
            print("⚠️  Email Channel not configured")
    
    def send_verification_code(self, to_email: str, code: str, username: str):
        """Send OTP via email using Resend"""
        if not self.enabled:
            print("⚠️  Email service not available")
            return False
            
        try:
            params = {
                "from": self.from_email,
                "to": [to_email],
                "subject": "🔐 TSMCA Security Verification Code",
                "html": f
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
                        .container {{ max-width: 600px; margin: 40px auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; }}
                        .header h1 {{ margin: 0; font-size: 28px; }}
                        .content {{ padding: 40px 30px; }}
                        .code-box {{ background: #f8f9fa; border: 3px solid #667eea; border-radius: 8px; padding: 25px; text-align: center; margin: 30px 0; }}
                        .code {{ font-size: 36px; font-weight: bold; color: #667eea; letter-spacing: 10px; font-family: 'Courier New', monospace; }}
                        .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; color: #856404; }}
                        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; font-size: 12px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <div style="font-size: 48px; margin-bottom: 10px;">🔐</div>
                            <h1>TSMCA Authentication</h1>
                        </div>
                        <div class="content">
                            <p style="font-size: 16px;">Hello <strong>{username}</strong>,</p>
                            <p>Your verification code is:</p>
                            <div class="code-box">
                                <div class="code">{code}</div>
                            </div>
                            <div class="warning">
                                <strong>⏰ Important:</strong> This code expires in <strong>60 seconds</strong>.
                            </div>
                            <p>If you didn't request this, please ignore this email.</p>
                        </div>
                        <div class="footer">
                            <p>© 2026 TSMCA Authentication System</p>
                        </div>
                    </div>
                </body>
                </html>
            
            response = resend.Emails.send(params)
            print(f"✅ Email sent successfully to {to_email}: {response['id']}")
            return True
        except Exception as e:
            print(f"❌ Email delivery failed to {to_email}: {str(e)}")
            return False

            # Initialize channels
sms_channel = SMSChannel()
email_channel = EmailChannel()

def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table with phone number
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
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
            failure_reason TEXT,
            channels_used TEXT
        )
    """)
    
    # Verification codes table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            code TEXT,
            channel TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT,
            used INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

# Pydantic Models
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
    channels: list[str]  # ["sms", "email", "app"]

class AuthResponse(BaseModel):
    success: bool
    session_token: Optional[str] = None
    expires_at: Optional[str] = None
    message: str
    qr_code_data: Optional[str] = None
    channels_used: Optional[list] = None

class TokenVerification(BaseModel):
    username: str
    token: str

# Helper Functions
def generate_user_id():
    return secrets.token_hex(16)

def generate_session_token():
    return secrets.token_urlsafe(32)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_auth_event(user_id: str, ip: str, device_id: str, method: str, status: str, reason: str = None, channels: list = None):
    """Log authentication event"""
    conn = get_db_connection()
    cursor = conn.cursor()
    channels_str = ','.join(channels) if channels else None
    cursor.execute("""
        INSERT INTO auth_logs (user_id, ip_address, device_id, auth_method, status, failure_reason, channels_used)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, ip, device_id, method, status, reason, channels_str))
    conn.commit()
    conn.close()

def check_account_locked(user_id: str) -> bool:
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
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()
    return False

def increment_failed_attempts(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT failed_attempts FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    
    if result:
        failed_attempts = result['failed_attempts'] + 1
        
        if failed_attempts >= 5:
            locked_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            cursor.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                         (failed_attempts, locked_until, user_id))
        else:
            cursor.execute("UPDATE users SET failed_attempts = ? WHERE user_id = ?",
                         (failed_attempts, user_id))
        
        conn.commit()
    conn.close()

def reset_failed_attempts(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET failed_attempts = 0 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def is_device_trusted(user_id: str, device_id: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT device_id FROM trusted_devices WHERE user_id = ? AND device_id = ?",
                  (user_id, device_id))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def add_trusted_device(user_id: str, device_id: str, device_type: str = "unknown"):
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
        "version": "2.0.0",
        "features": {
            "sms_verification": sms_channel.enabled,
            "email_verification": email_channel.enabled,
            "totp_authentication": True
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/register", response_model=AuthResponse)
async def register_user(user: UserRegistration, request: Request):
    """Register a new user and generate TOTP secret"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT user_id FROM users WHERE username = ? OR email = ?",
                  (user.username, user.email))
    existing = cursor.fetchone()
    
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    user_id = generate_user_id()
    totp_secret = pyotp.random_base32()
    password_hash = hash_password(user.password)
    
    cursor.execute("""
        INSERT INTO users (user_id, username, email, phone_number, shared_secret)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, user.username, user.email, user.phone_number, totp_secret))
    
    conn.commit()
    conn.close()
    
    totp = pyotp.TOTP(totp_secret)
    qr_uri = totp.provisioning_uri(name=user.email, issuer_name="TSMCA Auth")
    
    log_auth_event(user_id, request.client.host, "registration", "REGISTRATION", "SUCCESS")
    
    return AuthResponse(
        success=True,
        message="User registered successfully. Scan QR code with authenticator app.",
        qr_code_data=qr_uri
    )

@app.post("/api/v1/send-verification")
async def send_verification(request_data: MultiChannelAuthRequest, request: Request):
    """Send verification codes via specified channels"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (request_data.username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = user['user_id']
    totp = pyotp.TOTP(user['shared_secret'])
    verification_code = totp.now()
    
    channels_used = []
    channels_failed = []
    
    # Send via requested channels
    if "sms" in request_data.channels:
        if user['phone_number']:
            if sms_channel.send_verification_code(user['phone_number'], verification_code):
                channels_used.append("SMS")
            else:
                channels_failed.append("SMS")
        else:
            channels_failed.append("SMS (no phone number)")
    
    if "email" in request_data.channels:
        if email_channel.send_verification_code(user['email'], verification_code, user['username']):
            channels_used.append("Email")
        else:
            channels_failed.append("Email")
    
    if "app" in request_data.channels:
        channels_used.append("Authenticator App")
    
    conn.close()
    
    if not channels_used:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send verification code. Failures: {', '.join(channels_failed)}"
        )
    
    log_auth_event(user_id, request.client.host, request_data.device_id, 
                  "MULTI_CHANNEL_VERIFICATION", "SENT", channels=channels_used)
    
    return {
        "success": True,
        "message": f"Verification code sent successfully",
        "channels_used": channels_used,
        "channels_failed": channels_failed if channels_failed else None,
        "code_valid_for": "60 seconds"
    }

@app.post("/api/v1/authenticate", response_model=AuthResponse)
async def authenticate(auth: AuthRequest, request: Request):
    """Authenticate user with TOTP token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (auth.username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = user['user_id']
    
    if check_account_locked(user_id):
        log_auth_event(user_id, request.client.host, auth.device_id, "TOTP", "FAILURE", "Account locked")
        conn.close()
        raise HTTPException(status_code=403, detail="Account is locked. Please try again later.")
    
    totp = pyotp.TOTP(user['shared_secret'])
    
    if not totp.verify(auth.token, valid_window=1):
        increment_failed_attempts(user_id)
        log_auth_event(user_id, request.client.host, auth.device_id, "TOTP", "FAILURE", "Invalid token")
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid authentication token")
        reset_failed_attempts(user_id)
    
    device_trusted = is_device_trusted(user_id, auth.device_id)
    
    if not device_trusted:
        add_trusted_device(user_id, auth.device_id)
    
    session_token = generate_session_token()
    expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    
    cursor.execute("""
        INSERT INTO sessions (session_token, user_id, device_id, ip_address, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (session_token, user_id, auth.device_id, request.client.host, expires_at))
    
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
        SELECT s.*, u.username, u.email, u.phone_number
        FROM sessions s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.session_token = ?
    """, (session_token,))
    session = cursor.fetchone()
    conn.close()
    
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session token")
    
    expires_at = datetime.fromisoformat(session['expires_at'])
    if datetime.utcnow() > expires_at:
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
    """Logout and invalidate session"""
    session_token = credentials.credentials
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Logged out successfully"}

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
        "channels_status": {
            "sms_enabled": sms_channel.enabled,
            "email_enabled": email_channel.enabled
        },
        "last_24h": {
            "successful_authentications": successful_auths_24h,
            "failed_authentications": failed_auths_24h
        }
    }
    if name == "main":
    import os
    port = int(os.environ.get("PORT", 8000))
    
    print("=" * 60)
    print("TSMCA Authentication Server v2.0 Starting...")
    print("=" * 60)
    print(f"Server will be available on port: {port}")
    print(f"SMS Verification: {'✅ Enabled' if sms_channel.enabled else '❌ Disabled'}")
    print(f"Email Verification: {'✅ Enabled' if email_channel.enabled else '❌ Disabled'}")
    print("API Documentation: /docs")
    print("=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
