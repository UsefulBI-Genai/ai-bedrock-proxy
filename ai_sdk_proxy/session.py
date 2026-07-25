"""
Session management for AI SDK Proxy.

Handles token storage, refresh, and the developer-facing login command.

Single login command covers everything:
  ai-sdk login                    # lists available SSO profiles to pick from
  ai-sdk login --profile my-prof  # uses specific AWS SSO profile

This runs `aws sso login` for the chosen profile (opens browser → Okta once),
then extracts the Okta JWT from the SSO OIDC cache and stores both:
  - AWS credentials  → managed by AWS CLI in ~/.aws/sso/cache/
  - Okta JWT        → cached in ~/.ai_sdk/session.json

Session file: ~/.ai_sdk/session.json

CLI usage:
    ai-sdk login                    # pick profile interactively
    ai-sdk login --profile <name>   # use specific profile
    ai-sdk logout
    ai-sdk whoami
    ai-sdk token

Programmatic usage:
    from ai_sdk_proxy.session import AISdkSession
    session = AISdkSession()
    token = session.get_token()   # auto-refreshes if needed
"""

import base64
import configparser
import hashlib
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
import getpass
import logging
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Optional

import boto3

try:
    import certifi
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CONTEXT = ssl.create_default_context()

from .exceptions import ProxyAuthError

logger = logging.getLogger(__name__)

SESSION_DIR  = Path.home() / ".ai_sdk"
SESSION_FILE = SESSION_DIR / "session.json"

# Okta app config.
# Resolution order:
#   1. Environment variable (AI_SDK_OKTA_CLIENT_ID / AI_SDK_OKTA_ISSUER)
#   2. AWS SSO session cache (~/.aws/sso/cache/) — custom fields set by IT
#   3. AWS config profile — ai_sdk_okta_client_id / ai_sdk_okta_issuer fields
#   4. None — login will give a clear error
OKTA_REDIRECT = os.environ.get("AI_SDK_OKTA_REDIRECT", "http://localhost:8765/callback")
OKTA_SCOPES   = "openid profile email offline_access"
CALLBACK_PORT = 8765


# ---------------------------------------------------------------------------
# AWS SSO profile helpers
# ---------------------------------------------------------------------------

def _list_sso_profiles() -> list[dict]:
    """
    Parse ~/.aws/config and return all profiles that have SSO configured.
    Handles both formats:
      - New style (AWS CLI v2): profile has sso_session = <name>,
        actual start_url is in [sso-session <name>] section
      - Old style: profile has sso_start_url directly
    """
    config_file = Path.home() / ".aws" / "config"
    if not config_file.exists():
        return []

    # Use RawConfigParser with a non-standard default_section so [default]
    # is treated as a regular section instead of Python's special DEFAULT fallback
    config = configparser.RawConfigParser()
    config.default_section = "__unused_default__"
    config.read(config_file)

    # Build a lookup of sso-session name → start_url + region
    sso_sessions: dict[str, dict] = {}
    for section in config.sections():
        if section.startswith("sso-session "):
            session_name = section[len("sso-session "):]
            sso_sessions[session_name] = {
                "sso_start_url": config.get(section, "sso_start_url", fallback=""),
                "sso_region":    config.get(section, "sso_region",    fallback="us-east-1"),
            }

    profiles = []
    for section in config.sections():
        if section == "default":
            name = "default"
        elif section.startswith("profile "):
            name = section[len("profile "):]
        else:
            continue

        # Resolve start_url — new style via sso_session reference, old style inline
        sso_session_name = config.get(section, "sso_session", fallback=None)
        if sso_session_name and sso_session_name in sso_sessions:
            start_url  = sso_sessions[sso_session_name]["sso_start_url"]
            sso_region = sso_sessions[sso_session_name]["sso_region"]
        else:
            start_url  = config.get(section, "sso_start_url", fallback=None)
            sso_region = config.get(section, "sso_region",    fallback="us-east-1")

        if not start_url:
            continue  # not an SSO profile

        profiles.append({
            "name":                   name,
            "sso_start_url":          start_url,
            "sso_account_id":         config.get(section, "sso_account_id", fallback=""),
            "sso_role_name":          config.get(section, "sso_role_name",  fallback=""),
            "sso_region":             sso_region,
            "ai_sdk_okta_client_id":  config.get(section, "ai_sdk_okta_client_id", fallback=None),
            "ai_sdk_okta_issuer":     config.get(section, "ai_sdk_okta_issuer",     fallback=None),
        })

    return profiles


def _pick_profile(profile_name: Optional[str]) -> dict:
    """
    Resolve a profile by name, or prompt the user to pick one interactively.
    Raises ProxyAuthError if no SSO profiles exist.
    """
    profiles = _list_sso_profiles()
    if not profiles:
        raise ProxyAuthError(
            "No AWS SSO profiles found in ~/.aws/config.\n"
            "Ask your IT team to set up your AWS SSO profile, then re-run ai-sdk login."
        )

    if profile_name:
        match = next((p for p in profiles if p["name"] == profile_name), None)
        if not match:
            names = ", ".join(p["name"] for p in profiles)
            raise ProxyAuthError(
                f"Profile '{profile_name}' not found. Available SSO profiles: {names}"
            )
        return match

    if len(profiles) == 1:
        print(f"Using SSO profile: {profiles[0]['name']}")
        return profiles[0]

    # Multiple profiles — let user pick
    print("Available AWS SSO profiles:")
    for i, p in enumerate(profiles, 1):
        print(f"  {i}. {p['name']}  ({p['sso_role_name']} @ {p['sso_account_id']})")
    while True:
        try:
            choice = int(input(f"Select profile [1-{len(profiles)}]: ").strip())
            if 1 <= choice <= len(profiles):
                return profiles[choice - 1]
        except (ValueError, KeyboardInterrupt):
            pass
        print(f"  Enter a number between 1 and {len(profiles)}")


def _run_aws_sso_login(profile_name: str) -> bool:
    """
    Run `aws sso login --profile <name>` as a subprocess.
    Returns True on success.
    """
    print(f"\nRunning: aws sso login --profile {profile_name}")
    print("A browser window will open for authentication ...\n")
    result = subprocess.run(
        ["aws", "sso", "login", "--profile", profile_name],
        check=False,
    )
    return result.returncode == 0


def _okta_jwt_from_sso_cache(profile: dict) -> Optional[str]:
    """
    After `aws sso login`, the AWS CLI stores OIDC tokens in ~/.aws/sso/cache/.
    Find the token file matching this profile's start_url and extract the id_token.
    Returns the raw JWT string or None if not found.
    """
    sso_cache_dir = Path.home() / ".aws" / "sso" / "cache"
    if not sso_cache_dir.exists():
        return None

    start_url = profile.get("sso_start_url", "")

    # Walk all cache files, find the one for this start_url with a valid token
    for cache_file in sorted(sso_cache_dir.glob("*.json"),
                             key=lambda f: f.stat().st_mtime, reverse=True):
        try:
            data = json.loads(cache_file.read_text())
            if data.get("startUrl") != start_url:
                continue
            id_token = data.get("idToken") or data.get("id_token")
            if id_token:
                logger.debug("Found Okta JWT in SSO cache: %s", cache_file.name)
                return id_token
        except (json.JSONDecodeError, OSError):
            continue

    return None


def _okta_config_from_sso_cache() -> tuple[Optional[str], Optional[str]]:
    """
    Read Okta client_id and issuer from the most recently written AWS SSO cache file
    that contains custom ai_sdk_* fields (set by IT in the AWS config profile).
    Falls back to None if not found.
    """
    sso_cache_dir = Path.home() / ".aws" / "sso" / "cache"
    if not sso_cache_dir.exists():
        return None, None

    for cache_file in sorted(sso_cache_dir.glob("*.json"),
                             key=lambda f: f.stat().st_mtime, reverse=True):
        try:
            data = json.loads(cache_file.read_text())
            client_id = data.get("ai_sdk_okta_client_id")
            issuer    = data.get("ai_sdk_okta_issuer")
            if client_id and issuer:
                logger.debug("Okta config loaded from SSO cache: %s", cache_file.name)
                return client_id, issuer
        except (json.JSONDecodeError, OSError):
            continue

    return None, None


def _resolve_okta_config(profile: Optional[dict] = None) -> tuple[Optional[str], Optional[str]]:
    """
    Resolve Okta client_id and issuer with fallback chain:
      1. Environment variables
      2. AWS config profile fields (ai_sdk_okta_client_id / ai_sdk_okta_issuer)
      3. AWS SSO cache
    """
    client_id = os.environ.get("AI_SDK_OKTA_CLIENT_ID")
    issuer    = os.environ.get("AI_SDK_OKTA_ISSUER")
    if client_id and issuer:
        return client_id, issuer

    if profile:
        client_id = profile.get("ai_sdk_okta_client_id")
        issuer    = profile.get("ai_sdk_okta_issuer")
        if client_id and issuer:
            return client_id, issuer

    return _okta_config_from_sso_cache()


# Module-level resolution without a profile — for non-login uses
OKTA_CLIENT_ID, OKTA_ISSUER = _resolve_okta_config()


# ---------------------------------------------------------------------------
# Session file helpers
# ---------------------------------------------------------------------------

def _load_session() -> dict:
    if not SESSION_FILE.exists():
        return {}
    try:
        return json.loads(SESSION_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_session(data: dict) -> None:
    SESSION_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    SESSION_FILE.write_text(json.dumps(data, indent=2))
    SESSION_FILE.chmod(0o600)   # owner read/write only


def _clear_session() -> None:
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


# ---------------------------------------------------------------------------
# Okta PKCE helpers
# ---------------------------------------------------------------------------

def _pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge (S256)."""
    verifier  = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _okta_login_browser() -> dict:
    """
    Full Okta PKCE Authorization Code flow.
    Opens the browser, spins up a local HTTP server to catch the redirect,
    exchanges the code for tokens, and returns the token dict.
    No client secret used.
    """
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)

    # Build the authorization URL
    params = urllib.parse.urlencode({
        "client_id":             OKTA_CLIENT_ID,
        "response_type":         "code",
        "scope":                 OKTA_SCOPES,
        "redirect_uri":          OKTA_REDIRECT,
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    })
    auth_url = f"{OKTA_ISSUER}/v1/authorize?{params}"

    # Shared dict for the callback server to write the auth code into
    result: dict = {}

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed   = urllib.parse.urlparse(self.path)
            query    = urllib.parse.parse_qs(parsed.query)
            code     = query.get("code", [None])[0]
            returned = query.get("state", [None])[0]

            if returned != state:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"State mismatch. Please try again.")
                return

            result["code"] = code
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h2>Login successful!</h2>"
                b"<p>You can close this tab and return to the terminal.</p>"
                b"</body></html>"
            )

        def log_message(self, *args):
            pass  # suppress access log noise

    server = HTTPServer(("localhost", CALLBACK_PORT), CallbackHandler)

    # Open browser
    import webbrowser
    print(f"Opening browser for Okta login ...")
    print(f"If the browser does not open, visit:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    # Wait for the callback (one request only)
    server.handle_request()
    server.server_close()

    code = result.get("code")
    if not code:
        raise ProxyAuthError("No authorization code received from Okta")

    # Exchange code for tokens
    token_url  = f"{OKTA_ISSUER}/v1/token"
    token_data = urllib.parse.urlencode({
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  OKTA_REDIRECT,
        "client_id":     OKTA_CLIENT_ID,
        "code_verifier": verifier,
    }).encode()

    req = urllib.request.Request(
        token_url,
        data=token_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=_SSL_CONTEXT) as resp:
            tokens = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise ProxyAuthError(f"Okta token exchange failed: {e.code} {body}") from e

    return tokens


def _okta_refresh(refresh_token: str) -> dict:
    """Exchange a refresh token for new tokens. No client secret needed."""
    token_url  = f"{OKTA_ISSUER}/v1/token"
    token_data = urllib.parse.urlencode({
        "grant_type":    "refresh_token",
        "refresh_token": refresh_token,
        "client_id":     OKTA_CLIENT_ID,
        "scope":         OKTA_SCOPES,
    }).encode()

    req = urllib.request.Request(
        token_url,
        data=token_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=_SSL_CONTEXT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise ProxyAuthError(f"Okta token refresh failed: {e.code} {body}") from e


# ---------------------------------------------------------------------------
# AISdkSession — programmatic interface
# ---------------------------------------------------------------------------

class AISdkSession:
    """
    Manages the local token cache and silent refresh.

    Reads config from the session file written by `ai-sdk login`.
    Can also be constructed directly for non-interactive/service use.

    Example (developer, after running `ai-sdk login`):
        session = AISdkSession()
        token = session.get_token()

    Example (service / CI, explicit config):
        session = AISdkSession(
            client_id="...",
            user_pool_id="us-east-1_xxx",
            region="us-east-1",
        )
        token = session.get_token_with_password("user@example.com", "password")
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        user_pool_id: Optional[str] = None,
        region: Optional[str] = "us-east-1",
    ):
        session = _load_session()
        self._client_id    = client_id    or session.get("client_id")
        self._user_pool_id = user_pool_id or session.get("user_pool_id")
        self._region       = region       or session.get("region", "us-east-1")
        self._session      = session

    def _cognito(self):
        return boto3.client("cognito-idp", region_name=self._region)

    # -- Token access --------------------------------------------------------

    def get_token(self) -> str:
        """
        Return a valid (non-expired) ID token.
        Refreshes silently using the cached refresh token if needed.
        Raises ProxyAuthError if no session exists (user needs to login).
        """
        session = _load_session()

        if not session:
            raise ProxyAuthError(
                "No session found. Run: python3 -m ai_sdk_proxy.session login"
            )

        # Check if current id_token is still valid (with 60s buffer)
        expiry = session.get("expiry", 0)
        if time.time() < expiry - 60:
            return session["id_token"]

        # Expired — try silent refresh
        refresh_token = session.get("refresh_token")
        if not refresh_token:
            raise ProxyAuthError(
                "Session expired and no refresh token found. "
                "Run: python3 -m ai_sdk_proxy.session login"
            )

        print("  Refreshing token ...", file=sys.stderr)
        return self._refresh(refresh_token, session)

    def _refresh(self, refresh_token: str, session: dict) -> str:
        """Use the refresh token to get a new id_token silently."""
        idp = session.get("idp", "cognito")

        if idp == "okta":
            try:
                tokens = _okta_refresh(refresh_token)
                new_session = {
                    **session,
                    "id_token":     tokens["id_token"],
                    "access_token": tokens["access_token"],
                    "expiry":       int(time.time()) + tokens["expires_in"],
                    # Okta may or may not return a new refresh_token — keep old if absent
                    "refresh_token": tokens.get("refresh_token", refresh_token),
                }
                _save_session(new_session)
                print("  Token refreshed (Okta).", file=sys.stderr)
                return new_session["id_token"]
            except ProxyAuthError:
                _clear_session()
                raise ProxyAuthError(
                    "Okta refresh token expired. Run: python3 -m ai_sdk_proxy.session login --idp okta"
                )

        # Cognito refresh
        client_id = self._client_id or session.get("client_id")
        if not client_id:
            raise ProxyAuthError("client_id not found in session. Re-run login.")

        try:
            cognito = self._cognito()
            response = cognito.initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={"REFRESH_TOKEN": refresh_token},
                ClientId=client_id,
            )
            result = response["AuthenticationResult"]
            new_session = {
                **session,
                "id_token":    result["IdToken"],
                "access_token": result["AccessToken"],
                "expiry":      int(time.time()) + result["ExpiresIn"],
            }
            _save_session(new_session)
            print("  Token refreshed (Cognito).", file=sys.stderr)
            return new_session["id_token"]
        except cognito.exceptions.NotAuthorizedException:
            _clear_session()
            raise ProxyAuthError(
                "Refresh token has expired. Run: python3 -m ai_sdk_proxy.session login"
            )

    def get_token_with_password(self, username: str, password: str) -> str:
        """
        Authenticate with username + password and cache the session.
        Use for non-interactive/service scenarios.
        """
        if not self._client_id:
            raise ProxyAuthError("client_id is required for password auth")

        cognito = self._cognito()
        try:
            response = cognito.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": username,
                    "PASSWORD": password,
                },
                ClientId=self._client_id,
            )
        except cognito.exceptions.NotAuthorizedException:
            raise ProxyAuthError("Invalid username or password")
        except cognito.exceptions.UserNotFoundException:
            raise ProxyAuthError(f"User not found: {username}")

        result = response["AuthenticationResult"]
        session = {
            "id_token":     result["IdToken"],
            "access_token": result["AccessToken"],
            "refresh_token": result["RefreshToken"],
            "expiry":       int(time.time()) + result["ExpiresIn"],
            "client_id":    self._client_id,
            "user_pool_id": self._user_pool_id,
            "region":       self._region,
            "username":     username,
        }
        _save_session(session)
        return result["IdToken"]

    def whoami(self) -> Optional[dict]:
        """Return basic info about the currently logged-in user."""
        session = _load_session()
        if not session:
            return None
        # For Okta sessions, decode email from id_token
        username = session.get("username")
        if not username and session.get("id_token"):
            try:
                import base64 as _b64
                parts   = session["id_token"].split(".")
                padding = "=" * (-len(parts[1]) % 4)
                payload = json.loads(_b64.urlsafe_b64decode(parts[1] + padding))
                username = payload.get("email") or payload.get("preferred_username") or payload.get("sub")
            except Exception:
                pass
        return {
            "username":  username,
            "expiry":    session.get("expiry"),
            "region":    session.get("region"),
            "client_id": session.get("client_id"),
            "idp":       session.get("idp", "cognito"),
        }


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_login(args: list) -> int:
    """
    Unified login — runs aws sso login for the chosen profile (opens browser once),
    then extracts and caches the Okta JWT from the SSO result.

    Usage:
      ai-sdk login                    # pick from available SSO profiles
      ai-sdk login --profile <name>   # use a specific profile
      ai-sdk login --idp cognito      # Cognito username+password (CI/service accounts)
    """
    if "--idp" in args:
        idx = args.index("--idp")
        idp = args[idx + 1] if idx + 1 < len(args) else "okta"
        if idp == "cognito":
            return _cmd_login_cognito()

    profile_name = None
    if "--profile" in args:
        idx = args.index("--profile")
        profile_name = args[idx + 1] if idx + 1 < len(args) else None

    return _cmd_login_sso(profile_name)


def _cmd_login_sso(profile_name: Optional[str]) -> int:
    """
    Unified SSO + Okta login.
    1. Picks/confirms the AWS SSO profile.
    2. Runs `aws sso login --profile <name>` (opens browser → Okta).
    3. Extracts the Okta JWT from the SSO OIDC cache.
    4. Falls back to standalone PKCE flow if JWT not in SSO cache.
    5. Saves session to ~/.ai_sdk/session.json.
    """
    try:
        profile = _pick_profile(profile_name)
    except ProxyAuthError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Step 1: aws sso login
    if not _run_aws_sso_login(profile["name"]):
        print("AWS SSO login failed. Please try again.", file=sys.stderr)
        return 1

    # Step 2: try to get Okta JWT from SSO cache
    id_token = _okta_jwt_from_sso_cache(profile)

    # Step 3: if SSO cache doesn't have id_token, fall back to standalone PKCE
    if not id_token:
        print("\nOkta JWT not found in SSO cache — running standalone Okta login ...")
        okta_client_id, okta_issuer = _resolve_okta_config(profile)
        if not okta_client_id or not okta_issuer:
            print(
                "Error: Okta client ID and issuer are not configured.\n"
                "Add ai_sdk_okta_client_id and ai_sdk_okta_issuer to your AWS profile\n"
                "or set AI_SDK_OKTA_CLIENT_ID and AI_SDK_OKTA_ISSUER env vars.",
                file=sys.stderr,
            )
            return 1
        # Temporarily override module-level globals for the PKCE flow
        global OKTA_CLIENT_ID, OKTA_ISSUER
        OKTA_CLIENT_ID = okta_client_id
        OKTA_ISSUER    = okta_issuer
        try:
            tokens   = _okta_login_browser()
            id_token = tokens.get("id_token")
            refresh_token = tokens.get("refresh_token", "")
            expires_in    = tokens.get("expires_in", 3600)
        except ProxyAuthError as e:
            print(f"Okta login failed: {e}", file=sys.stderr)
            return 1
    else:
        refresh_token = ""
        # Decode expiry from the JWT payload
        try:
            parts   = id_token.split(".")
            padding = "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
            expires_in = max(0, int(payload.get("exp", time.time() + 3600) - time.time()))
        except Exception:
            expires_in = 3600

    # Step 4: decode and display identity
    try:
        parts   = id_token.split(".")
        padding = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
        email   = payload.get("email") or payload.get("preferred_username") or payload.get("sub", "unknown")
        issuer  = payload.get("iss", "")
    except Exception:
        email  = "unknown"
        issuer = ""

    session = {
        "id_token":     id_token,
        "refresh_token": refresh_token,
        "expiry":       int(time.time()) + expires_in,
        "idp":          "okta",
        "issuer":       issuer,
        "aws_profile":  profile["name"],
    }
    _save_session(session)

    print(f"\nLogged in as : {email}")
    print(f"AWS profile  : {profile['name']}")
    print(f"IDP          : Okta (via AWS SSO)")
    print(f"Expires      : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['expiry']))}")
    print(f"Session saved: {SESSION_FILE}")
    return 0


def _cmd_login_cognito() -> int:
    """Cognito username + password login."""
    session = _load_session()
    client_id    = os.environ.get("AI_SDK_COGNITO_CLIENT_ID")    or session.get("client_id")
    user_pool_id = os.environ.get("AI_SDK_COGNITO_USER_POOL_ID") or session.get("user_pool_id")
    region       = os.environ.get("AI_SDK_COGNITO_REGION")       or session.get("region", "us-east-1")

    if not client_id:
        client_id = input("Cognito App Client ID: ").strip()
    if not user_pool_id:
        user_pool_id = input("Cognito User Pool ID: ").strip()

    username = input("Email: ").strip()
    password = getpass.getpass("Password: ")

    sdk_session = AISdkSession(
        client_id=client_id,
        user_pool_id=user_pool_id,
        region=region,
    )
    try:
        sdk_session.get_token_with_password(username, password)
        info = sdk_session.whoami()
        print(f"\nLogged in as : {info['username']}")
        print(f"IDP          : Cognito")
        print(f"Expires      : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['expiry']))}")
        print(f"Session saved: {SESSION_FILE}")
        return 0
    except ProxyAuthError as e:
        print(f"Login failed: {e}", file=sys.stderr)
        return 1


def cmd_logout(args: list) -> int:
    """Clear the local session cache."""
    _clear_session()
    print("Logged out. Session cleared.")
    return 0


def cmd_token(args: list) -> int:
    """Print the current valid ID token (refreshing if needed). Suitable for scripting."""
    try:
        sdk_session = AISdkSession()
        token = sdk_session.get_token()
        print(token)   # stdout only — suitable for $(ai-sdk token)
        return 0
    except ProxyAuthError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_whoami(args: list) -> int:
    """Print info about the currently logged-in user."""
    sdk_session = AISdkSession()
    info = sdk_session.whoami()
    if not info:
        print("Not logged in.")
        print("  Okta   : python3 -m ai_sdk_proxy.session login --idp okta")
        print("  Cognito: python3 -m ai_sdk_proxy.session login")
        return 1
    expiry_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["expiry"]))
    remaining  = max(0, int(info["expiry"] - time.time()))
    print(f"User      : {info['username']}")
    print(f"IDP       : {info.get('idp', 'cognito')}")
    print(f"Client ID : {info['client_id']}")
    print(f"Expires   : {expiry_str} ({remaining}s remaining)")
    return 0


_COMMANDS = {
    "login":  cmd_login,
    "logout": cmd_logout,
    "token":  cmd_token,
    "whoami": cmd_whoami,
}

_USAGE = """\
AI SDK Proxy — session management

Commands:
  login                      Authenticate via AWS SSO + Okta (browser, one login for both)
  login --profile <name>     Use a specific AWS SSO profile
  login --idp cognito        Cognito username + password (for CI/service accounts)
  logout                     Clear the local session cache
  token                      Print current valid ID token (auto-refreshes)
  whoami                     Show current logged-in user and token expiry

Examples:
  ai-sdk login                    # lists SSO profiles, pick one, browser opens
  ai-sdk login --profile ai-dev   # use specific profile directly
  ai-sdk whoami
  ai-sdk logout
"""


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(_USAGE)
        return 0

    cmd = args[0]
    if cmd not in _COMMANDS:
        print(f"Unknown command: {cmd}\n", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return 1

    return _COMMANDS[cmd](args[1:])


if __name__ == "__main__":
    sys.exit(main())
