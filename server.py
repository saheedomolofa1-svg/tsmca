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

# Initialize FastAPI
app = FastAPI(
    title="TSMCA Authentication Server",
    description="Multi-Channel Authentication System",
    version="2.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
            return True
        except Exception as e:
            print(f"❌ Email failed: {e}")
            return False

# Initialize channels
sms_channel = SMSChannel()
email_channel = EmailChannel()

# ─── Database ────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone_number TEXT,
        shared_secret TEXT NOT NULL,
        password_hash TEXT,
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
        device_name TEXT,
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

    # ── Migrations: add new columns to existing DBs ──────────
    migrations = [
        "ALTER TABLE users ADD COLUMN password_hash TEXT",
        "ALTER TABLE trusted_devices ADD COLUMN device_name TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
            conn.commit()
        except Exception:
            pass  # Column already exists — safe to ignore

    conn.close()

init_db()

# ─── Pydantic Models ─────────────────────────────────────────
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

# ── NEW: Profile & Password models ───────────────────────────
class UpdateProfileRequest(BaseModel):
    email: Optional[str] = None
    phone_number: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    current_password: Optional[str] = None   # Optional for users who registered without password
    new_password: str

# ─── Helpers ────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def log_auth(user_id, ip, device_id, method, status, reason=None, channels=None):
    conn = get_db()
    c = conn.cursor()
    channels_str = ','.join(channels) if channels else None
    c.execute("""INSERT INTO auth_logs (user_id, ip_address, device_id, auth_method, status, failure_reason, channels_used)
        VALUES (?, ?, ?, ?, ?, ?, ?)""", (user_id, ip, device_id, method, status, reason, channels_str))
    conn.commit()
    conn.close()

def is_locked(user_id):
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

def increment_failures(user_id):
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

def reset_failures(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET failed_attempts = 0 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def is_trusted(user_id, device_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT device_id FROM trusted_devices WHERE user_id = ? AND device_id = ?", (user_id, device_id))
    result = c.fetchone()
    conn.close()
    return result is not None

def add_device(user_id, device_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("""INSERT OR REPLACE INTO trusted_devices (device_id, user_id, device_fingerprint, device_type, device_name, last_used)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (device_id, user_id, device_id, "unknown", f"Device ({device_id[:8]})", datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def get_session_user(token: str):
    """Return (session_row, user_row) or raise 401."""
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT s.*, u.username, u.email, u.phone_number, u.password_hash
        FROM sessions s JOIN users u ON s.user_id = u.user_id
        WHERE s.session_token = ? AND s.expires_at > ?""",
        (token, datetime.utcnow().isoformat()))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return row

# ════════════════════════════════════════════════════════════
# ORIGINAL ENDPOINTS (unchanged)
# ════════════════════════════════════════════════════════════

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
    pw_hash = hash_password(user.password) if user.password else None

    c.execute("""INSERT INTO users (user_id, username, email, phone_number, shared_secret, password_hash)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, user.username, user.email, user.phone_number, secret, pw_hash))
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
    else:
        # Update last_used on existing device
        conn2 = get_db()
        conn2.execute("UPDATE trusted_devices SET last_used = ? WHERE device_id = ? AND user_id = ?",
                      (datetime.utcnow().isoformat(), auth.device_id, user_id))
        conn2.commit()
        conn2.close()

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

@app.get("/api/v1/users/{username}/devices")
async def get_user_devices(username: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    c.execute("""SELECT device_id, device_name, device_type, trust_level, first_seen, last_used
        FROM trusted_devices WHERE user_id = ?""", (user['user_id'],))
    devices = c.fetchall()
    conn.close()
    return {"username": username, "devices": [dict(d) for d in devices]}

@app.get("/api/v1/users/{username}/activity")
async def get_user_activity(username: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    c.execute("""SELECT timestamp, ip_address, device_id, auth_method, status, failure_reason, channels_used
        FROM auth_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20""", (user['user_id'],))
    logs = c.fetchall()
    conn.close()
    return {"username": username, "activity": [dict(log) for log in logs]}

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
        "channels_status": {"sms_enabled": sms_channel.enabled, "email_enabled": email_channel.enabled},
        "last_24h": {"successful_authentications": successful_24h, "failed_authentications": failed_24h}
    }

# ════════════════════════════════════════════════════════════
# FEATURE 2 — DEVICE MANAGEMENT
# ════════════════════════════════════════════════════════════

@app.get("/api/v1/devices")
async def list_my_devices(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """List all trusted devices for the logged-in user, marking which is current."""
    session = get_session_user(credentials.credentials)
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT device_id, device_name, device_type, trust_level, first_seen, last_used
        FROM trusted_devices WHERE user_id = ?
        ORDER BY last_used DESC""", (session['user_id'],))
    rows = c.fetchall()
    conn.close()

    devices = []
    for r in rows:
        devices.append({
            "device_id":   r['device_id'],
            "device_name": r['device_name'] or f"Device ({r['device_id'][:8]})",
            "device_type": r['device_type'],
            "trust_level": r['trust_level'],
            "first_seen":  r['first_seen'],
            "last_used":   r['last_used'],
            "is_current":  r['device_id'] == session['device_id']
        })
    return {"devices": devices}


@app.delete("/api/v1/devices/{device_id}")
async def revoke_device(device_id: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Revoke a trusted device. Cannot revoke the device you are currently using."""
    session = get_session_user(credentials.credentials)

    if device_id == session['device_id']:
        raise HTTPException(status_code=400, detail="Cannot revoke your current device. Use logout instead.")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT device_id FROM trusted_devices WHERE device_id = ? AND user_id = ?",
              (device_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    # Kill all sessions on that device
    c.execute("DELETE FROM sessions WHERE device_id = ? AND user_id = ?",
              (device_id, session['user_id']))
    # Remove the device
    c.execute("DELETE FROM trusted_devices WHERE device_id = ? AND user_id = ?",
              (device_id, session['user_id']))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Device revoked and its sessions terminated"}


# ════════════════════════════════════════════════════════════
# FEATURE 3 — UPDATE PROFILE & CHANGE PASSWORD
# ════════════════════════════════════════════════════════════

@app.put("/api/v1/profile")
async def update_profile(data: UpdateProfileRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Update email and/or phone number for the logged-in user."""
    session = get_session_user(credentials.credentials)
    user_id = session['user_id']

    conn = get_db()
    c = conn.cursor()

    if data.email:
        # Check not already taken
        c.execute("SELECT user_id FROM users WHERE email = ? AND user_id != ?", (data.email, user_id))
        if c.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Email already in use by another account")
        c.execute("UPDATE users SET email = ? WHERE user_id = ?", (data.email, user_id))

    if data.phone_number is not None:
        c.execute("UPDATE users SET phone_number = ? WHERE user_id = ?", (data.phone_number, user_id))

    conn.commit()

    # Return updated user data
    c.execute("SELECT username, email, phone_number FROM users WHERE user_id = ?", (user_id,))
    updated = c.fetchone()
    conn.close()

    return {
        "success": True,
        "message": "Profile updated successfully",
        "user": {
            "username": updated['username'],
            "email": updated['email'],
            "phone_number": updated['phone_number']
        }
    }


@app.put("/api/v1/change-password")
async def change_password(data: ChangePasswordRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Change account password. If no password was set at registration, current_password can be omitted."""
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    session = get_session_user(credentials.credentials)
    user_id = session['user_id']

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()

    if row['password_hash']:
        # Password exists — require current password
        if not data.current_password:
            conn.close()
            raise HTTPException(status_code=400, detail="Current password is required")
        if hash_password(data.current_password) != row['password_hash']:
            conn.close()
            raise HTTPException(status_code=401, detail="Current password is incorrect")

    new_hash = hash_password(data.new_password)
    c.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (new_hash, user_id))

    # Invalidate all OTHER sessions so other devices must re-authenticate
    c.execute("DELETE FROM sessions WHERE user_id = ? AND session_token != ?",
              (user_id, credentials.credentials))
    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Password updated. All other sessions have been logged out for security."
    }


# ════════════════════════════════════════════════════════════
# FEATURE 4 — SESSION MANAGEMENT
# ════════════════════════════════════════════════════════════

@app.get("/api/v1/sessions")
async def list_sessions(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """List all active sessions for the logged-in user."""
    session = get_session_user(credentials.credentials)
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT s.session_token, s.device_id, s.ip_address, s.created_at, s.expires_at,
                        td.device_name,
                        CASE WHEN s.session_token = ? THEN 1 ELSE 0 END as is_current
               FROM sessions s
               LEFT JOIN trusted_devices td ON s.device_id = td.device_id
               WHERE s.user_id = ? AND s.expires_at > ?
               ORDER BY s.created_at DESC""",
              (credentials.credentials, session['user_id'], datetime.utcnow().isoformat()))
    rows = c.fetchall()
    conn.close()

    sessions = []
    for r in rows:
        sessions.append({
            "session_token": r['session_token'],
            "device_id":     r['device_id'],
            "device_name":   r['device_name'] or f"Device ({r['device_id'][:8]})",
            "ip_address":    r['ip_address'],
            "created_at":    r['created_at'],
            "expires_at":    r['expires_at'],
            "is_current":    bool(r['is_current'])
        })
    return {"sessions": sessions}


@app.delete("/api/v1/sessions/all-others")
async def terminate_all_other_sessions(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Terminate ALL sessions except the current one."""
    session = get_session_user(credentials.credentials)
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM sessions WHERE user_id = ? AND session_token != ?",
              (session['user_id'], credentials.credentials))
    count = c.rowcount
    conn.commit()
    conn.close()
    return {"success": True, "message": f"Terminated {count} other session(s)"}


@app.delete("/api/v1/sessions/{token}")
async def terminate_session(token: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Terminate a specific session by token. Cannot terminate your current session."""
    session = get_session_user(credentials.credentials)

    if token == credentials.credentials:
        raise HTTPException(status_code=400, detail="Use /logout to end your current session")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT session_token FROM sessions WHERE session_token = ? AND user_id = ?",
              (token, session['user_id']))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Session not found")

    c.execute("DELETE FROM sessions WHERE session_token = ? AND user_id = ?",
              (token, session['user_id']))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Session terminated"}


# ════════════════════════════════════════════════════════════
# PAGE ROUTES & ADMIN ENDPOINTS (unchanged)
# ════════════════════════════════════════════════════════════

from fastapi.responses import HTMLResponse

@app.get("/app", response_class=HTMLResponse)
async def serve_client():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        html_content = html_content.replace(
            "const API_BASE = 'https://govtamca.onrender.com/api/v1';",
            "const API_BASE = '/api/v1';"
        )
        return html_content
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Client file not found.</h1>", status_code=404)


@app.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    try:
        with open("admin.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse(content="""
        <html><body style="font-family: Arial; padding: 40px; text-align: center;">
            <h1>🛡️ Admin Dashboard</h1>
            <p>Admin panel file not found.</p>
            <p><a href="/docs" style="color: #667eea;">Go to API Documentation</a></p>
        </body></html>
        """)


@app.get("/api/v1/admin/recent-activity")
async def admin_recent_activity():
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT a.timestamp, u.username, a.auth_method, a.ip_address, a.status
        FROM auth_logs a LEFT JOIN users u ON a.user_id = u.user_id
        ORDER BY a.timestamp DESC LIMIT 50""")
    activity = c.fetchall()
    conn.close()
    return {"activity": [dict(row) for row in activity]}


@app.get("/api/v1/admin/users")
async def admin_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT user_id, username, email, phone_number, created_at, last_login, account_status
        FROM users ORDER BY created_at DESC""")
    users = c.fetchall()
    conn.close()
    return {"users": [dict(row) for row in users]}
# ── Add this endpoint to server.py alongside the other admin endpoints ──

@app.get("/api/v1/admin/all-devices")
async def admin_all_devices():
    """Return all trusted devices across all users (used for device count in admin table)."""
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT device_id, user_id, device_name, device_type, trust_level, first_seen, last_used
                 FROM trusted_devices
                 ORDER BY last_used DESC""")
    devices = c.fetchall()
    conn.close()
    return {"devices": [dict(d) for d in devices]}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print("=" * 60)
    print("TSMCA Authentication Server v2.0")
    print("=" * 60)
    print(f"Port: {port}")
    print(f"SMS:   {'✅ Enabled' if sms_channel.enabled else '❌ Disabled'}")
    print(f"Email: {'✅ Enabled' if email_channel.enabled else '❌ Disabled'}")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
