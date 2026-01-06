"""
Simple OAuth client for OneDrive Backup Tool.

This module provides a SimpleAuth class that handles authentication via a hosted
auth service, making it easy for users to "Login with Microsoft" without needing
to set up their own Azure app registration.

Usage:
    from auth_client import SimpleAuth

    auth = SimpleAuth()
    if auth.is_logged_in():
        auth.refresh_token()
    else:
        auth.login()

    # Use auth.access_token for API calls
"""

import os
import json
import secrets
import string
import hashlib
import base64
import webbrowser
import threading
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests

# Configuration
AUTH_SERVICE_URL = os.environ.get('AUTH_SERVICE_URL', 'https://onedrive-auth-service.your-domain.workers.dev')
LOCAL_CALLBACK_PORT = 8400
SESSION_FILE = Path.home() / '.onedrive_backup_session.json'


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback"""

    # Class-level storage for callback data
    callback_code = None
    callback_state = None
    callback_error = None

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

    def do_GET(self):
        """Handle OAuth callback GET request"""
        parsed = urlparse(self.path)

        if parsed.path == '/callback':
            params = parse_qs(parsed.query)

            if 'error' in params:
                CallbackHandler.callback_error = params.get('error_description', params['error'])[0]
                self._send_error_page()
            elif 'code' in params:
                CallbackHandler.callback_code = params['code'][0]
                CallbackHandler.callback_state = params.get('state', [None])[0]
                self._send_success_page()
            else:
                self._send_error_page('No authorization code received')
        else:
            self.send_response(404)
            self.end_headers()

    def _send_success_page(self):
        """Send success HTML page"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        html = '''<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(255,255,255,0.1);
            border-radius: 16px;
            backdrop-filter: blur(10px);
        }
        .checkmark {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 { margin: 0 0 10px 0; }
        p { opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">&#10004;</div>
        <h1>Login Successful!</h1>
        <p>You can close this window and return to the backup tool.</p>
    </div>
</body>
</html>'''
        self.wfile.write(html.encode())

    def _send_error_page(self, error=None):
        """Send error HTML page"""
        self.send_response(400)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        error_msg = error or CallbackHandler.callback_error or 'Unknown error'
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Login Failed</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
        }}
        .container {{
            text-align: center;
            padding: 40px;
            background: rgba(255,255,255,0.1);
            border-radius: 16px;
            backdrop-filter: blur(10px);
        }}
        .error-icon {{ font-size: 64px; margin-bottom: 20px; }}
        h1 {{ margin: 0 0 10px 0; }}
        p {{ opacity: 0.9; max-width: 400px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">&#10060;</div>
        <h1>Login Failed</h1>
        <p>{error_msg}</p>
        <p>Please close this window and try again.</p>
    </div>
</body>
</html>'''
        self.wfile.write(html.encode())


class SimpleAuth:
    """
    Simple OAuth client for OneDrive Backup Tool.

    Handles authentication via a hosted auth service, providing a seamless
    "Login with Microsoft" experience without requiring users to set up
    their own Azure app registration.

    Attributes:
        access_token (str): Current access token for API calls
        user_id (str): Hashed user identifier
        service_url (str): URL of the auth service
    """

    def __init__(self, service_url: str = None):
        """
        Initialize SimpleAuth.

        Args:
            service_url: Optional custom auth service URL
        """
        self.service_url = service_url or AUTH_SERVICE_URL
        self.access_token = None
        self.user_id = None
        self._token_expires_at = None
        self._code_verifier = None
        self._state = None

        # Load existing session if available
        self._load_session()

    def _generate_code_verifier(self) -> str:
        """Generate a cryptographically random PKCE code verifier"""
        # RFC 7636: 43-128 characters from [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        alphabet = string.ascii_letters + string.digits + '-._~'
        return ''.join(secrets.choice(alphabet) for _ in range(64))

    def _load_session(self):
        """Load session data from file"""
        if SESSION_FILE.exists():
            try:
                with open(SESSION_FILE, 'r') as f:
                    data = json.load(f)
                    self.user_id = data.get('user_id')
                    self._token_expires_at = data.get('expires_at')
            except (json.JSONDecodeError, IOError):
                pass

    def _save_session(self):
        """Save session data to file"""
        try:
            data = {
                'user_id': self.user_id,
                'expires_at': self._token_expires_at,
            }
            with open(SESSION_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            # Secure the file (only user can read/write)
            os.chmod(SESSION_FILE, 0o600)
        except IOError as e:
            print(f"Warning: Could not save session: {e}")

    def _clear_session(self):
        """Clear session data"""
        self.access_token = None
        self.user_id = None
        self._token_expires_at = None
        if SESSION_FILE.exists():
            try:
                SESSION_FILE.unlink()
            except IOError:
                pass

    def is_logged_in(self) -> bool:
        """
        Check if user has a valid session.

        Returns:
            bool: True if user has a stored session (may need refresh)
        """
        return self.user_id is not None

    def login(self) -> bool:
        """
        Start OAuth login flow.

        Opens browser for Microsoft login, starts local server to catch callback,
        and exchanges authorization code for tokens via the auth service.

        Returns:
            bool: True if login successful, False otherwise
        """
        print("\n" + "=" * 50)
        print("Login with Microsoft")
        print("=" * 50)

        # Generate PKCE code verifier
        self._code_verifier = self._generate_code_verifier()

        # Reset callback handler state
        CallbackHandler.callback_code = None
        CallbackHandler.callback_state = None
        CallbackHandler.callback_error = None

        # Step 1: Get auth URL from service
        print("\n1. Requesting authorization URL...")
        try:
            response = requests.post(
                f"{self.service_url}/auth/login",
                json={'code_verifier': self._code_verifier},
                timeout=30
            )

            if response.status_code != 200:
                error = response.json().get('error', 'Unknown error')
                print(f"   Failed to get auth URL: {error}")
                return False

            data = response.json()
            auth_url = data['auth_url']
            self._state = data['state']

        except requests.RequestException as e:
            print(f"   Failed to connect to auth service: {e}")
            return False

        # Step 2: Start local callback server
        print("2. Starting local callback server...")
        server = HTTPServer(('localhost', LOCAL_CALLBACK_PORT), CallbackHandler)
        server.timeout = 300  # 5 minute timeout

        server_thread = threading.Thread(target=lambda: server.handle_request())
        server_thread.daemon = True
        server_thread.start()

        # Step 3: Open browser for login
        print("3. Opening browser for Microsoft login...")
        print(f"\n   If browser doesn't open, visit:\n   {auth_url[:80]}...\n")
        webbrowser.open(auth_url)

        # Step 4: Wait for callback
        print("4. Waiting for login (timeout: 5 minutes)...")
        server_thread.join(timeout=300)

        # Check for errors
        if CallbackHandler.callback_error:
            print(f"\n   Login failed: {CallbackHandler.callback_error}")
            return False

        if not CallbackHandler.callback_code:
            print("\n   Login timed out. Please try again.")
            return False

        # Verify state matches (CSRF protection)
        if CallbackHandler.callback_state != self._state:
            print("\n   Security error: State mismatch. Please try again.")
            return False

        # Step 5: Exchange code for tokens
        print("5. Exchanging authorization code for tokens...")
        try:
            response = requests.post(
                f"{self.service_url}/auth/callback",
                json={
                    'code': CallbackHandler.callback_code,
                    'code_verifier': self._code_verifier,
                    'state': self._state,
                },
                timeout=30
            )

            if response.status_code != 200:
                error = response.json().get('error', 'Unknown error')
                details = response.json().get('details', '')
                print(f"   Token exchange failed: {error}")
                if details:
                    print(f"   Details: {details}")
                return False

            data = response.json()
            self.access_token = data['access_token']
            self.user_id = data['user_id']
            self._token_expires_at = time.time() + data.get('expires_in', 3600)

            # Save session
            self._save_session()

            print("\n" + "=" * 50)
            print("Login successful!")
            print("=" * 50 + "\n")
            return True

        except requests.RequestException as e:
            print(f"   Token exchange failed: {e}")
            return False

    def refresh_token(self) -> bool:
        """
        Refresh the access token using stored refresh token.

        Returns:
            bool: True if refresh successful, False otherwise
        """
        if not self.user_id:
            print("Not logged in. Please login first.")
            return False

        print("Refreshing access token...")

        try:
            response = requests.post(
                f"{self.service_url}/auth/refresh",
                json={'user_id': self.user_id},
                timeout=30
            )

            if response.status_code == 401:
                # Session expired, need to login again
                print("Session expired. Please login again.")
                self._clear_session()
                return False

            if response.status_code != 200:
                error = response.json().get('error', 'Unknown error')
                print(f"Token refresh failed: {error}")
                return False

            data = response.json()
            self.access_token = data['access_token']
            self._token_expires_at = time.time() + data.get('expires_in', 3600)

            print("Token refreshed successfully!")
            return True

        except requests.RequestException as e:
            print(f"Token refresh failed: {e}")
            return False

    def logout(self) -> None:
        """
        Logout and clear all stored tokens.
        """
        if self.user_id:
            try:
                requests.post(
                    f"{self.service_url}/auth/logout",
                    json={'user_id': self.user_id},
                    timeout=30
                )
            except requests.RequestException:
                pass  # Best effort - continue with local cleanup

        self._clear_session()
        print("Logged out successfully.")

    def ensure_valid_token(self) -> bool:
        """
        Ensure we have a valid access token, refreshing if needed.

        Returns:
            bool: True if we have a valid token, False otherwise
        """
        if not self.is_logged_in():
            return self.login()

        # Check if token is expired or close to expiring (5 min buffer)
        if self._token_expires_at and time.time() > (self._token_expires_at - 300):
            return self.refresh_token()

        # If we have a user_id but no access_token, refresh
        if not self.access_token:
            return self.refresh_token()

        return True


# For testing
if __name__ == '__main__':
    auth = SimpleAuth()

    if auth.is_logged_in():
        print("Existing session found. Refreshing token...")
        if auth.refresh_token():
            print(f"Access token: {auth.access_token[:20]}...")
        else:
            print("Refresh failed. Attempting new login...")
            auth.login()
    else:
        print("No existing session. Starting login...")
        auth.login()

    if auth.access_token:
        print(f"\nSuccess! Access token: {auth.access_token[:20]}...")
