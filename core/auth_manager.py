"""
Authentication Manager
Manages authenticated scanning with cookie, bearer token, and form-based login.
"""
import aiohttp
import asyncio
import time
from urllib.parse import urlparse, urljoin


class AuthMethod:
    NONE = "none"
    COOKIE = "cookie"
    BEARER = "bearer"
    FORM_LOGIN = "form_login"


class AuthManager:
    """Manages authentication state for scan sessions."""
    
    def __init__(self, log_callback=None):
        self.method = AuthMethod.NONE
        self.log = log_callback or (lambda msg: None)
        
        # Cookie auth
        self._cookies = {}
        self._raw_cookie_string = ""
        
        # Bearer token auth
        self._bearer_token = ""
        
        # Form login auth
        self._login_url = ""
        self._username_field = "username"
        self._password_field = "password"
        self._username = ""
        self._password = ""
        self._session_cookies = {}
        
        # Session validation
        self._validation_url = ""
        self._validation_keyword = ""  # Keyword that must appear in response to confirm session is valid
        
        # State
        self._authenticated = False
        self._last_check = 0
        self._check_interval = 60  # Re-check session every 60 seconds
    
    def configure_cookies(self, cookie_string):
        """Configure cookie-based authentication."""
        if not cookie_string or not cookie_string.strip():
            return
        self.method = AuthMethod.COOKIE
        self._raw_cookie_string = cookie_string.strip()
        self._cookies = self._parse_cookies(cookie_string)
        self._authenticated = True
        self.log(f"🔐 Auth: Cookie-based authentication configured ({len(self._cookies)} cookies)")
    
    def configure_bearer(self, token):
        """Configure bearer token authentication."""
        if not token or not token.strip():
            return
        self.method = AuthMethod.BEARER
        self._bearer_token = token.strip()
        # Remove "Bearer " prefix if user included it
        if self._bearer_token.lower().startswith("bearer "):
            self._bearer_token = self._bearer_token[7:]
        self._authenticated = True
        self.log(f"🔐 Auth: Bearer token configured ({len(self._bearer_token)} chars)")
    
    def configure_form_login(self, login_url, username_field, password_field, username, password):
        """Configure form-based login authentication."""
        if not login_url or not username or not password:
            return
        self.method = AuthMethod.FORM_LOGIN
        self._login_url = login_url.strip()
        self._username_field = username_field.strip() or "username"
        self._password_field = password_field.strip() or "password"
        self._username = username.strip()
        self._password = password.strip()
        self.log(f"🔐 Auth: Form login configured → {self._login_url}")
    
    def configure_validation(self, validation_url, keyword=""):
        """Configure session validation endpoint."""
        if validation_url and validation_url.strip():
            self._validation_url = validation_url.strip()
            self._validation_keyword = keyword.strip() or ""
            self.log(f"🔐 Auth: Session validation → {self._validation_url}")
    
    async def login(self, session=None):
        """Perform form-based login and capture session cookies."""
        if self.method != AuthMethod.FORM_LOGIN:
            return True
        
        try:
            close_session = False
            if session is None:
                session = aiohttp.ClientSession()
                close_session = True
            
            login_data = {
                self._username_field: self._username,
                self._password_field: self._password
            }
            
            async with session.post(self._login_url, data=login_data, allow_redirects=True, ssl=False) as resp:
                # Capture cookies from response
                for cookie in session.cookie_jar:
                    self._session_cookies[cookie.key] = cookie.value
                
                if resp.status in (200, 302, 301):
                    self._authenticated = True
                    self.log(f"✅ Auth: Login successful → {len(self._session_cookies)} session cookies captured")
                else:
                    self._authenticated = False
                    self.log(f"❌ Auth: Login failed → HTTP {resp.status}")
            
            if close_session:
                await session.close()
            
            return self._authenticated
            
        except Exception as e:
            self.log(f"❌ Auth: Login error → {str(e)}")
            self._authenticated = False
            return False
    
    async def validate_session(self, session=None):
        """Check if current session is still valid."""
        if not self._validation_url or not self._authenticated:
            return self._authenticated
        
        # Rate-limit checks
        now = time.time()
        if now - self._last_check < self._check_interval:
            return self._authenticated
        self._last_check = now
        
        try:
            close_session = False
            if session is None:
                session = aiohttp.ClientSession()
                close_session = True
            
            headers = self.get_headers()
            async with session.get(self._validation_url, headers=headers, ssl=False) as resp:
                if resp.status == 401 or resp.status == 403:
                    self._authenticated = False
                    self.log("⚠️ Auth: Session expired — attempting re-authentication")
                    await self.re_authenticate(session)
                elif self._validation_keyword:
                    body = await resp.text()
                    if self._validation_keyword not in body:
                        self._authenticated = False
                        self.log("⚠️ Auth: Session validation keyword not found — re-authenticating")
                        await self.re_authenticate(session)
            
            if close_session:
                await session.close()
                
        except Exception as e:
            self.log(f"⚠️ Auth: Validation error → {str(e)}")
        
        return self._authenticated
    
    async def re_authenticate(self, session=None):
        """Re-authenticate if session expired."""
        if self.method == AuthMethod.FORM_LOGIN:
            self.log("🔄 Auth: Re-authenticating via form login...")
            return await self.login(session)
        return self._authenticated
    
    def get_headers(self):
        """Get authentication headers to inject into requests."""
        headers = {}
        
        if self.method == AuthMethod.BEARER:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        elif self.method == AuthMethod.COOKIE:
            headers["Cookie"] = self._raw_cookie_string
        elif self.method == AuthMethod.FORM_LOGIN and self._session_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
            headers["Cookie"] = cookie_str
        
        return headers
    
    def get_cookies_dict(self):
        """Get cookies as a dictionary for aiohttp session."""
        if self.method == AuthMethod.COOKIE:
            return self._cookies
        elif self.method == AuthMethod.FORM_LOGIN:
            return self._session_cookies
        return {}
    
    @property
    def is_authenticated(self):
        return self._authenticated
    
    @property
    def auth_type_label(self):
        labels = {
            AuthMethod.NONE: "None",
            AuthMethod.COOKIE: "Cookie",
            AuthMethod.BEARER: "Bearer Token",
            AuthMethod.FORM_LOGIN: "Form Login"
        }
        return labels.get(self.method, "Unknown")
    
    @staticmethod
    def _parse_cookies(cookie_string):
        """Parse cookie string into dict. Handles 'Cookie: k=v; k2=v2' and 'k=v; k2=v2' formats."""
        cookies = {}
        raw = cookie_string.strip()
        # Remove "Cookie: " prefix if present
        if raw.lower().startswith("cookie:"):
            raw = raw[7:].strip()
        
        for pair in raw.split(";"):
            pair = pair.strip()
            if "=" in pair:
                key, value = pair.split("=", 1)
                cookies[key.strip()] = value.strip()
        
        return cookies
