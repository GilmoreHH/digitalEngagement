"""
Magic Link Authentication System - Production Secure Version
Enhanced security features for organizational use
"""

import streamlit as st
import os
import time
import jwt
import secrets
import requests
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import re
from typing import Optional, Tuple, Dict
from collections import defaultdict
import base64

# Load environment variables
load_dotenv()

class RateLimiter:
    """Rate limiting for authentication attempts"""
    
    def __init__(self):
        self.attempts = defaultdict(list)
        self.max_attempts = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
        self.lockout_minutes = int(os.getenv("LOCKOUT_DURATION_MINUTES", "30"))
        self.cleanup_interval = 100  # Clean up old attempts every 100 checks
        self.check_count = 0
    
    def is_rate_limited(self, identifier: str) -> Tuple[bool, Optional[str]]:
        """Check if an identifier (email/IP) is rate limited"""
        now = datetime.now(timezone.utc)
        self.check_count += 1
        
        # Periodic cleanup of old attempts
        if self.check_count % self.cleanup_interval == 0:
            self._cleanup_old_attempts()
        
        # Get attempts for this identifier
        attempts = self.attempts[identifier]
        
        # Filter to only recent attempts within lockout window
        lockout_window = timedelta(minutes=self.lockout_minutes)
        recent_attempts = [
            attempt for attempt in attempts 
            if now - attempt < lockout_window
        ]
        
        # Update the attempts list
        self.attempts[identifier] = recent_attempts
        
        # Check if rate limited
        if len(recent_attempts) >= self.max_attempts:
            # Calculate time until unlock
            oldest_attempt = min(recent_attempts)
            unlock_time = oldest_attempt + lockout_window
            remaining_minutes = int((unlock_time - now).total_seconds() / 60)
            
            return True, f"Too many attempts. Please try again in {remaining_minutes} minutes."
        
        return False, None
    
    def record_attempt(self, identifier: str):
        """Record a login attempt"""
        self.attempts[identifier].append(datetime.now(timezone.utc))
    
    def reset_attempts(self, identifier: str):
        """Reset attempts for a successful login"""
        if identifier in self.attempts:
            del self.attempts[identifier]
    
    def _cleanup_old_attempts(self):
        """Remove old attempts from memory"""
        now = datetime.now(timezone.utc)
        lockout_window = timedelta(minutes=self.lockout_minutes)
        
        for identifier in list(self.attempts.keys()):
            self.attempts[identifier] = [
                attempt for attempt in self.attempts[identifier]
                if now - attempt < lockout_window
            ]
            
            # Remove empty entries
            if not self.attempts[identifier]:
                del self.attempts[identifier]

class SecureSessionManager:
    """Secure session management with encryption"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()
        self.sessions = {}  # In-memory session store
        self.session_timeout = timedelta(hours=int(os.getenv("SESSION_EXPIRY_HOURS", "8")))
        self.last_cleanup = datetime.now(timezone.utc)
    
    def create_session_id(self) -> str:
        """Create a secure session ID"""
        return secrets.token_urlsafe(32)
    
    def create_session_signature(self, session_id: str, user_data: dict) -> str:
        """Create HMAC signature for session data"""
        data_str = json.dumps(user_data, sort_keys=True)
        signature = hmac.new(
            self.secret_key,
            f"{session_id}{data_str}".encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def store_session(self, session_id: str, user_data: dict) -> str:
        """Store session data securely"""
        now = datetime.now(timezone.utc)
        
        # Clean up old sessions periodically
        if now - self.last_cleanup > timedelta(hours=1):
            self._cleanup_expired_sessions()
            self.last_cleanup = now
        
        # Store session with expiration
        session_data = {
            'user_data': user_data,
            'created_at': now,
            'expires_at': now + self.session_timeout,
            'last_activity': now,
            'signature': self.create_session_signature(session_id, user_data)
        }
        
        self.sessions[session_id] = session_data
        
        # Create secure token combining session_id and signature
        token_data = {
            'sid': session_id,
            'sig': session_data['signature'][:16]  # Include partial signature
        }
        
        # Encode as base64 for URL safety
        token = base64.urlsafe_b64encode(
            json.dumps(token_data).encode()
        ).decode().rstrip('=')
        
        return token
    
    def verify_session(self, token: str) -> Tuple[bool, Optional[dict]]:
        """Verify and retrieve session data"""
        try:
            # Decode token
            padded_token = token + '=' * (4 - len(token) % 4)
            token_data = json.loads(
                base64.urlsafe_b64decode(padded_token.encode()).decode()
            )
            
            session_id = token_data.get('sid')
            partial_sig = token_data.get('sig')
            
            if not session_id or session_id not in self.sessions:
                return False, None
            
            session = self.sessions[session_id]
            
            # Check expiration
            now = datetime.now(timezone.utc)
            if now > session['expires_at']:
                del self.sessions[session_id]
                return False, None
            
            # Verify signature
            if not session['signature'].startswith(partial_sig):
                return False, None
            
            # Update last activity
            session['last_activity'] = now
            
            # Extend session if actively used
            if now - session['created_at'] < timedelta(hours=1):
                session['expires_at'] = now + self.session_timeout
            
            return True, session['user_data']
            
        except Exception:
            return False, None
    
    def revoke_session(self, token: str):
        """Revoke a session"""
        try:
            padded_token = token + '=' * (4 - len(token) % 4)
            token_data = json.loads(
                base64.urlsafe_b64decode(padded_token.encode()).decode()
            )
            session_id = token_data.get('sid')
            
            if session_id and session_id in self.sessions:
                del self.sessions[session_id]
        except Exception:
            pass
    
    def _cleanup_expired_sessions(self):
        """Remove expired sessions from memory"""
        now = datetime.now(timezone.utc)
        expired = [
            sid for sid, session in self.sessions.items()
            if now > session['expires_at']
        ]
        for sid in expired:
            del self.sessions[sid]

class AuditLogger:
    """Security audit logging"""
    
    def __init__(self):
        self.enabled = os.getenv("ENABLE_AUDIT_LOG", "true").lower() == "true"
        self.log_file = os.getenv("AUDIT_LOG_FILE", "auth_audit.log")
    
    def log_event(self, event_type: str, email: str, success: bool, 
                  details: Optional[dict] = None, ip_address: Optional[str] = None):
        """Log security events"""
        if not self.enabled:
            return
        
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'email': email,
            'success': success,
            'ip_address': ip_address or 'unknown',
            'details': details or {}
        }
        
        # In production, send to proper logging service
        # For now, store in session state for admin review
        if 'audit_log' not in st.session_state:
            st.session_state.audit_log = []
        
        st.session_state.audit_log.append(event)
        
        # Keep only last 1000 events in memory
        if len(st.session_state.audit_log) > 1000:
            st.session_state.audit_log = st.session_state.audit_log[-1000:]

class MagicLinkAuth:
    """Enhanced passwordless authentication with security features"""
    
    def __init__(self):
        # Validate JWT secret strength
        self.jwt_secret = self._validate_jwt_secret()
        self.jwt_algorithm = "HS256"
        
        # Initialize security components
        self.rate_limiter = RateLimiter()
        self.session_manager = SecureSessionManager(self.jwt_secret)
        self.audit_logger = AuditLogger()
        
        # Load configuration
        self.config = self._load_config()
        
        # Validate production configuration
        if not self.config["development_mode"]:
            self._validate_production_config()
        
        self.authorized_users = self._load_authorized_users()
        
        # Get Microsoft Graph token if configured
        self.graph_token = None
        if self._is_email_configured():
            self.graph_token = self._get_graph_token()
    
    def _validate_jwt_secret(self) -> str:
        """Validate JWT secret meets security requirements"""
        jwt_secret = os.getenv("JWT_SECRET")
        
        if not jwt_secret:
            if os.getenv("DEVELOPMENT_MODE", "false").lower() == "true":
                # Generate a development secret
                jwt_secret = secrets.token_urlsafe(32)
            else:
                raise ValueError(
                    "JWT_SECRET environment variable is required in production. "
                    "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )
        
        # Check minimum length
        if len(jwt_secret) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters for security")
        
        # Check complexity (basic check)
        if jwt_secret.lower() == jwt_secret or jwt_secret.upper() == jwt_secret:
            if os.getenv("DEVELOPMENT_MODE", "false").lower() != "true":
                raise ValueError("JWT_SECRET should contain mixed case characters for better security")
        
        return jwt_secret
    
    def _validate_production_config(self):
        """Validate configuration for production deployment"""
        required_vars = [
            "JWT_SECRET",
            "COMPANY_NAME",
            "ALLOWED_EMAIL_DOMAINS",
            "ADMIN_EMAIL"
        ]
        
        missing = [var for var in required_vars if not os.getenv(var)]
        if missing:
            raise ValueError(f"Missing required environment variables for production: {missing}")
        
        # Ensure HTTPS in production (Streamlit Cloud handles this)
        dashboard_url = os.getenv("DASHBOARD_URL", "")
        if dashboard_url and not dashboard_url.startswith(("https://", "http://localhost")):
            raise ValueError("DASHBOARD_URL must use HTTPS in production")
    
    def _is_email_configured(self):
        """Check if email sending is configured"""
        return all([
            os.getenv("AZURE_TENANT_ID"),
            os.getenv("AZURE_CLIENT_ID"),
            os.getenv("AZURE_CLIENT_SECRET"),
            os.getenv("M365_SENDER_EMAIL")
        ])
    
    def _load_config(self):
        """Load configuration from environment variables"""
        allowed_domains_str = os.getenv("ALLOWED_EMAIL_DOMAINS", "company.com")
        allowed_domains = [d.strip().lower() for d in allowed_domains_str.replace('"', '').replace("'", '').split(",")]
        
        return {
            "company_name": os.getenv("COMPANY_NAME", "Company"),
            "allowed_domains": allowed_domains,
            
            "tenant_id": os.getenv("AZURE_TENANT_ID"),
            "client_id": os.getenv("AZURE_CLIENT_ID"),
            "client_secret": os.getenv("AZURE_CLIENT_SECRET"),
            
            "sender_email": os.getenv("M365_SENDER_EMAIL"),
            "sender_name": os.getenv("M365_SENDER_NAME", "System"),
            
            "token_expiry_minutes": int(os.getenv("TOKEN_EXPIRY_MINUTES", "15")),
            "session_expiry_hours": int(os.getenv("SESSION_EXPIRY_HOURS", "8")),
            
            "dashboard_name": os.getenv("DASHBOARD_NAME", "Dashboard"),
            "dashboard_icon": os.getenv("DASHBOARD_ICON", "📊"),
            "dashboard_url": os.getenv("DASHBOARD_URL", "https://localhost:8501"),
            
            "admin_email": os.getenv("ADMIN_EMAIL", "").strip().lower(),
            "ceo_email": os.getenv("CEO_EMAIL", "").strip().lower(),
            
            "development_mode": os.getenv("DEVELOPMENT_MODE", "false").lower() == "true",
            
            "support_contact": os.getenv("SUPPORT_CONTACT", "support"),
            
            # Security settings
            "enable_ip_check": os.getenv("ENABLE_IP_CHECK", "false").lower() == "true",
            "allowed_ips": os.getenv("ALLOWED_IPS", "").split(",") if os.getenv("ALLOWED_IPS") else [],
        }
    
    def _get_graph_token(self):
        """Get access token for Microsoft Graph API"""
        if not all([self.config["tenant_id"], self.config["client_id"], self.config["client_secret"]]):
            return None
        
        token_url = f"https://login.microsoftonline.com/{self.config['tenant_id']}/oauth2/v2.0/token"
        
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
            'scope': 'https://graph.microsoft.com/.default'
        }
        
        try:
            response = requests.post(token_url, data=token_data, timeout=10)
            response.raise_for_status()
            return response.json().get('access_token')
        except Exception:
            return None
    
    def _load_authorized_users(self):
        """Load authorized users from environment variables"""
        users = {}
        
        for i in range(1, 201):
            email = os.getenv(f"USER_{i}_EMAIL")
            if not email:
                continue
            
            email_lower = email.strip().lower()
            name = os.getenv(f"USER_{i}_NAME", email.split('@')[0])
            title = os.getenv(f"USER_{i}_TITLE", "")
            
            admin_email = self.config["admin_email"].strip().lower()
            ceo_email = self.config["ceo_email"].strip().lower()
            
            if email_lower == admin_email:
                user_type = "admin"
            elif email_lower == ceo_email:
                user_type = "ceo"
            else:
                user_type = "user"
            
            users[email_lower] = {
                "name": name,
                "title": title,
                "type": user_type
            }
        
        return users
    
    def create_magic_link_token(self, email: str, ip_address: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
        """Create a magic link token with rate limiting"""
        email = email.lower().strip()
        
        # Check rate limiting
        is_limited, limit_message = self.rate_limiter.is_rate_limited(email)
        if is_limited:
            self.audit_logger.log_event("magic_link_rate_limited", email, False, 
                                       {"reason": "rate_limit"}, ip_address)
            return False, limit_message, None
        
        # Record attempt
        self.rate_limiter.record_attempt(email)
        
        # Validate authorization
        if not self.is_authorized(email):
            valid, msg = self.validate_email(email)
            if not valid:
                self.audit_logger.log_event("magic_link_failed", email, False, 
                                           {"reason": "invalid_email"}, ip_address)
                return False, msg, None
            
            self.audit_logger.log_event("magic_link_failed", email, False, 
                                       {"reason": "unauthorized"}, ip_address)
            return False, os.getenv("UNAUTHORIZED_MESSAGE", "This email is not authorized to access the dashboard."), None
        
        try:
            # Create token with additional security claims
            payload = {
                'email': email,
                'type': 'magic_link',
                'exp': datetime.now(timezone.utc) + timedelta(minutes=self.config["token_expiry_minutes"]),
                'iat': datetime.now(timezone.utc),
                'jti': secrets.token_urlsafe(16),  # Unique token ID
                'ip': ip_address or 'unknown'
            }
            
            token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            magic_link = f"{self.config['dashboard_url']}?auth_token={token}"
            
            # Reset rate limiting on success
            self.rate_limiter.reset_attempts(email)
            
            self.audit_logger.log_event("magic_link_created", email, True, 
                                       {"expires_in_minutes": self.config["token_expiry_minutes"]}, 
                                       ip_address)
            
            return True, "", magic_link
            
        except Exception:
            self.audit_logger.log_event("magic_link_error", email, False, 
                                       {"reason": "token_generation_failed"}, ip_address)
            return False, os.getenv("GENERIC_ERROR_MESSAGE", "Error occurred"), None
    
    def verify_magic_link_token(self, token: str, ip_address: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """Verify a magic link token and create secure session"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            if payload.get('type') != 'magic_link':
                return False, None, os.getenv("INVALID_TOKEN_MESSAGE", "Invalid token")
            
            email = payload['email']
            
            # Verify user is still authorized
            if not self.is_authorized(email):
                self.audit_logger.log_event("magic_link_verify_failed", email, False, 
                                           {"reason": "user_no_longer_authorized"}, ip_address)
                return False, None, os.getenv("REVOKED_ACCESS_MESSAGE", "Access revoked")
            
            # Get user data
            user_data = self.authorized_users.get(email.lower(), {})
            
            # Create secure session
            session_id = self.session_manager.create_session_id()
            session_data = {
                'email': email,
                'name': user_data.get('name', email.split('@')[0]),
                'title': user_data.get('title', ''),
                'type': user_data.get('type', 'user'),
                'login_time': datetime.now(timezone.utc).isoformat(),
                'login_ip': ip_address or 'unknown'
            }
            
            session_token = self.session_manager.store_session(session_id, session_data)
            
            self.audit_logger.log_event("login_success", email, True, 
                                       {"session_id": session_id[:8]}, ip_address)
            
            return True, email, session_token
            
        except jwt.ExpiredSignatureError:
            self.audit_logger.log_event("magic_link_expired", "", False, None, ip_address)
            return False, None, os.getenv("EXPIRED_LINK_MESSAGE", "Link expired")
        except jwt.InvalidTokenError:
            self.audit_logger.log_event("magic_link_invalid", "", False, None, ip_address)
            return False, None, os.getenv("INVALID_LINK_MESSAGE", "Invalid link")
        except Exception:
            return False, None, os.getenv("GENERIC_ERROR_MESSAGE", "Error occurred")
    
    def verify_session_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """Verify a secure session token"""
        return self.session_manager.verify_session(token)
    
    def revoke_session(self, token: str, email: str = "unknown"):
        """Revoke a session on logout"""
        self.session_manager.revoke_session(token)
        self.audit_logger.log_event("logout", email, True, None, None)
    
    def send_magic_link_email(self, to_email, magic_link):
        """Send magic link email"""
        if not self._is_email_configured():
            return False, os.getenv("EMAIL_NOT_CONFIGURED_MESSAGE", "Email not configured")
        
        if not self.graph_token:
            self.graph_token = self._get_graph_token()
            if not self.graph_token:
                return False, os.getenv("EMAIL_SERVICE_ERROR_MESSAGE", "Email service error")
        
        user_info = self.authorized_users.get(to_email.lower(), {})
        user_name = user_info.get("name", to_email.split('@')[0])
        
        email_subject = os.getenv("EMAIL_SUBJECT", "Sign in to Dashboard").replace("{dashboard}", self.config['dashboard_name'])
        email_greeting = os.getenv("EMAIL_GREETING", "Hello").replace("{name}", user_name)
        email_body = os.getenv("EMAIL_BODY", "Click below to sign in").replace("{dashboard}", self.config['dashboard_name'])
        email_button_text = os.getenv("EMAIL_BUTTON_TEXT", "Sign In")
        email_footer = os.getenv("EMAIL_FOOTER", "Link expires in 15 minutes").replace("{minutes}", str(self.config['token_expiry_minutes']))
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: #f5f5f5; padding: 30px; border-radius: 10px;">
                <h2>{email_greeting}</h2>
                <p>{email_body}</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{magic_link}" style="background: #0066cc; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        {email_button_text}
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">{email_footer}</p>
                <p style="color: #999; font-size: 12px;">If you didn't request this, please ignore this email and contact your administrator.</p>
            </div>
        </body>
        </html>
        """
        
        send_mail_url = f"https://graph.microsoft.com/v1.0/users/{self.config['sender_email']}/sendMail"
        
        email_msg = {
            "message": {
                "subject": email_subject,
                "body": {
                    "contentType": "HTML",
                    "content": html_body
                },
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": to_email,
                            "name": user_name
                        }
                    }
                ]
            },
            "saveToSentItems": "false"
        }
        
        headers = {
            'Authorization': f'Bearer {self.graph_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.post(send_mail_url, headers=headers, json=email_msg, timeout=30)
            
            if response.status_code == 202:
                return True, ""
            elif response.status_code == 401:
                self.graph_token = self._get_graph_token()
                if self.graph_token:
                    headers['Authorization'] = f'Bearer {self.graph_token}'
                    response = requests.post(send_mail_url, headers=headers, json=email_msg, timeout=30)
                    if response.status_code == 202:
                        return True, ""
                return False, os.getenv("AUTH_EXPIRED_MESSAGE", "Authentication expired")
            else:
                return False, os.getenv("EMAIL_FAILED_MESSAGE", "Email failed")
                
        except Exception:
            return False, os.getenv("EMAIL_ERROR_MESSAGE", "Error sending email")
    
    def is_authorized(self, email):
        """Check if email is authorized"""
        email_clean = email.lower().strip()
        return email_clean in self.authorized_users
    
    def validate_email(self, email):
        """Validate email format and domain"""
        email = email.lower().strip()
        
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False, os.getenv("INVALID_EMAIL_FORMAT_MESSAGE", "Invalid email format")
        
        domain = email.split('@')[1].lower().strip()
        allowed = self.config["allowed_domains"]
        
        if domain not in allowed:
            return False, os.getenv("DOMAIN_NOT_ALLOWED_MESSAGE", f"Email domain not allowed")
        
        return True, "Valid"
    
    def generate_and_send_link(self, email, ip_address=None):
        """Generate and send magic link"""
        success, message, magic_link = self.create_magic_link_token(email, ip_address)
        
        if not success:
            return False, message
        
        email_success, email_message = self.send_magic_link_email(email, magic_link)
        
        if email_success:
            return True, ""  # Return empty string - no duplicate message
        else:
            if self.config["development_mode"]:
                st.session_state._dev_magic_link = magic_link
                return True, ""  # Return empty string for dev mode - no duplicate message
            return False, email_message

# Initialize auth system
@st.cache_resource
def get_auth_instance():
    return MagicLinkAuth()

auth = get_auth_instance()

# Session state initialization
def init_session_state():
    """Initialize session state"""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.session_token = None
        st.session_state.user_data = None
        st.session_state.show_users = False
        st.session_state._auth_initialized = True

def get_session_from_url():
    """Get session from URL"""
    return st.query_params.get("session")

def maintain_session_in_url():
    """Maintain session in URL"""
    if st.session_state.authenticated and st.session_state.session_token:
        st.query_params["session"] = st.session_state.session_token

def get_client_ip():
    """Try to get client IP address"""
    # In production, this would come from reverse proxy headers
    # For Streamlit Cloud, this is limited
    return None

# Login page
def show_login():
    """Display login page"""
    
    # Clear any stale magic link messages on page load
    if 'magic_link_email' in st.session_state:
        # Only clear if it's a different session or timeout
        if st.session_state.get('last_magic_link_time', 0) < time.time() - 10:
            if 'magic_link_sent' in st.session_state:
                del st.session_state.magic_link_sent
            if 'magic_link_email' in st.session_state:
                del st.session_state.magic_link_email
            if 'dev_link_to_show' in st.session_state:
                del st.session_state.dev_link_to_show
    
    # Check for auth token in URL
    if "auth_token" in st.query_params:
        with st.spinner(os.getenv("VERIFYING_MESSAGE", "Verifying...")):
            time.sleep(0.5)
            valid, email, session_token = auth.verify_magic_link_token(
                st.query_params["auth_token"], 
                get_client_ip()
            )
            
            if valid:
                st.session_state.authenticated = True
                st.session_state.session_token = session_token
                
                # Get user data from secure session
                valid_session, user_data = auth.verify_session_token(session_token)
                if valid_session:
                    st.session_state.user_data = user_data
                else:
                    # Fallback
                    email_lower = email.lower() if email else ""
                    user_data = auth.authorized_users.get(email_lower, {})
                    st.session_state.user_data = {
                        'email': email or 'unknown',
                        'name': user_data.get('name', 'User'),
                        'title': user_data.get('title', ''),
                        'type': user_data.get('type', 'user')
                    }
                
                st.query_params.clear()
                st.query_params["session"] = session_token
                
                time.sleep(0.5)
                st.rerun()
            else:
                st.error(session_token or os.getenv("INVALID_LINK_ERROR", "Invalid link"))
                st.query_params.clear()
                time.sleep(2)
                st.rerun()
    
    # Login UI
    st.markdown(f"""
        <div style='text-align: center; margin-bottom: 2rem;'>
            <h1 style='font-size: 3rem;'>{auth.config['dashboard_icon']}</h1>
            <h2>{auth.config['dashboard_name']}</h2>
            <p>{auth.config['company_name']}</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Login form
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("login_form"):
            st.markdown(f"### {os.getenv('LOGIN_TITLE', 'Sign In')}")
            
            email = st.text_input(
                os.getenv("EMAIL_LABEL", "Email"),
                placeholder=os.getenv("EMAIL_PLACEHOLDER", "email@company.com"),
                label_visibility="collapsed"
            )
            
            send_button = st.form_submit_button(
                os.getenv("SEND_BUTTON_TEXT", "Send Magic Link"),
                use_container_width=True,
                type="primary"
            )
            
            if email and send_button:
                # Prevent double processing on rerun
                if 'processing_magic_link' not in st.session_state:
                    st.session_state.processing_magic_link = True
                    
                    with st.spinner(os.getenv("SENDING_MESSAGE", "Sending...")):
                        time.sleep(0.5)
                        success, message = auth.generate_and_send_link(email, get_client_ip())
                        
                        if success:
                            st.session_state.magic_link_sent = True
                            st.session_state.magic_link_email = email
                            st.session_state.last_magic_link_time = time.time()
                            # Store dev link if in dev mode
                            if auth.config["development_mode"] and hasattr(st.session_state, '_dev_magic_link'):
                                st.session_state.dev_link_to_show = st.session_state._dev_magic_link
                        else:
                            st.session_state.magic_link_error = message
                    
                    # Clear processing flag and rerun to show message
                    del st.session_state.processing_magic_link
                    st.rerun()
            
            # Show success message outside of form to prevent doubles
            if 'magic_link_sent' in st.session_state and st.session_state.magic_link_sent:
                st.info(os.getenv("CHECK_EMAIL_MESSAGE", "Check your email for the magic link"))
                
                if auth.config["development_mode"] and 'dev_link_to_show' in st.session_state:
                    with st.expander("Development Mode - Magic Link"):
                        st.code(st.session_state.dev_link_to_show)
                
                # Clear the flag after showing
                st.session_state.magic_link_sent = False
                if 'dev_link_to_show' in st.session_state:
                    del st.session_state.dev_link_to_show
            
            # Show error message if any
            if 'magic_link_error' in st.session_state:
                st.error(st.session_state.magic_link_error)
                del st.session_state.magic_link_error
        
        st.markdown("---")
        st.caption(os.getenv("LOGIN_FOOTER", "Secure access"))
        st.caption(f"{os.getenv('SUPPORT_TEXT', 'Contact')} {auth.config['support_contact']}")

# Authentication decorator
def require_auth(func):
    """Require authentication decorator"""
    def wrapper(*args, **kwargs):
        init_session_state()
        
        if not st.session_state.authenticated:
            session_token = get_session_from_url()
            
            if session_token:
                valid, user_data = auth.verify_session_token(session_token)
                
                if valid and user_data:
                    st.session_state.authenticated = True
                    st.session_state.session_token = session_token
                    st.session_state.user_data = user_data
                else:
                    st.query_params.clear()
                    st.session_state.authenticated = False
        
        if st.session_state.authenticated:
            maintain_session_in_url()
            
            # Dashboard header
            col1, col2, col3 = st.columns([4, 1, 1])
            
            with col1:
                user = st.session_state.user_data
                
                if not user:
                    user = {'email': 'unknown', 'name': 'User', 'type': 'user', 'title': ''}
                
                user_email = user.get('email', 'unknown')
                user_name = user.get('name', 'User')
                user_type = user.get('type', 'user')
                user_title = user.get('title', '')
                
                if user_type == 'admin':
                    designation = os.getenv("ADMIN_DESIGNATION", "Administrator")
                elif user_type == 'ceo':
                    designation = os.getenv("CEO_DESIGNATION", "Chief Executive")
                elif user_title:
                    designation = user_title
                else:
                    designation = os.getenv("USER_DESIGNATION", "User")
                
                st.caption(f"👤 {user_name} | 📧 {user_email} | 🏷️ {designation}")
            
            with col2:
                if user_type == 'admin':
                    if st.button(os.getenv("USERS_BUTTON", "Users")):
                        st.session_state.show_users = not st.session_state.show_users
            
            with col3:
                if st.button(os.getenv("SIGNOUT_BUTTON", "Sign Out")):
                    # Revoke session
                    if st.session_state.session_token:
                        auth.revoke_session(
                            st.session_state.session_token,
                            user.get('email', 'unknown')
                        )
                    
                    # Clear session state
                    for key in list(st.session_state.keys()):
                        del st.session_state[key]
                    st.query_params.clear()
                    st.rerun()
            
            st.markdown("---")
            
            if st.session_state.get('show_users', False) and user_type == 'admin':
                show_authorized_users()
            else:
                func(*args, **kwargs)
        else:
            if get_session_from_url():
                st.warning(os.getenv("SESSION_EXPIRED_MESSAGE", "Session expired"))
            show_login()
    
    return wrapper

# Admin panel
def show_authorized_users():
    """Show authorized users and audit log (admin only)"""
    st.markdown(f"## {os.getenv('USERS_PANEL_TITLE', 'System Administration')}")
    
    tab1, tab2 = st.tabs(["👥 Users", "📋 Audit Log"])
    
    with tab1:
        st.info(f"{len(auth.authorized_users)} {os.getenv('USERS_COUNT_TEXT', 'users have access')}")
        
        if auth.authorized_users:
            users_data = []
            for email, data in sorted(auth.authorized_users.items()):
                if email == auth.config["admin_email"]:
                    access = os.getenv("ADMIN_ACCESS_TEXT", "Full Access (Admin)")
                elif email == auth.config["ceo_email"]:
                    access = os.getenv("CEO_ACCESS_TEXT", "Executive Access")
                else:
                    access = os.getenv("USER_ACCESS_TEXT", "View Only")
                
                users_data.append({
                    os.getenv("COL_EMAIL", "Email"): email,
                    os.getenv("COL_NAME", "Name"): data["name"],
                    os.getenv("COL_TITLE", "Title"): data.get("title", ""),
                    os.getenv("COL_ACCESS", "Access Level"): access
                })
            
            import pandas as pd
            df = pd.DataFrame(users_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            if st.button(os.getenv("EXPORT_BUTTON", "Export to CSV")):
                csv = df.to_csv(index=False)
                st.download_button(
                    label=os.getenv("DOWNLOAD_BUTTON", "Download CSV"),
                    data=csv,
                    file_name=f"users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
    
    with tab2:
        st.subheader("Security Audit Log")
        
        if 'audit_log' in st.session_state and st.session_state.audit_log:
            # Show recent events
            recent_events = st.session_state.audit_log[-100:]  # Last 100 events
            
            audit_data = []
            for event in reversed(recent_events):
                audit_data.append({
                    "Time": event['timestamp'],
                    "Event": event['event_type'],
                    "User": event['email'],
                    "Success": "✅" if event['success'] else "❌",
                    "IP": event.get('ip_address', 'unknown')
                })
            
            import pandas as pd
            audit_df = pd.DataFrame(audit_data)
            st.dataframe(audit_df, use_container_width=True, hide_index=True)
            
            # Export audit log
            if st.button("Export Audit Log", key="export_audit"):
                csv = audit_df.to_csv(index=False)
                st.download_button(
                    label="Download Audit CSV",
                    data=csv,
                    file_name=f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        else:
            st.info("No audit events recorded yet")
    
    if st.button(os.getenv("BACK_BUTTON", "Back")):
        st.session_state.show_users = False
        st.rerun()

# Export functions
__all__ = ['require_auth', 'init_session_state', 'get_auth_instance']
