"""
JWT validation and identity extraction.

Supports multiple issuers (Cognito, Okta, or any OIDC-compliant IDP).
The issuer is auto-detected from the 'iss' claim in the token.

Signature verification:
  - POC mode (default): decodes payload without verifying signature
  - Production mode: fetches JWKS from the issuer's well-known endpoint
    and verifies the RS256 signature

To enable production signature verification:
    pip install PyJWT[crypto] cryptography

Token flow:
    Developer    → Cognito USER_PASSWORD_AUTH  → Cognito JWT
    Business user → Okta Authorization Code    → Okta JWT
    Both JWTs    → AI SDK Proxy validate_and_extract() → identity dict
"""

import json
import os
import time
import base64
import logging
import urllib.request
from typing import Callable, Optional

from .exceptions import ProxyAuthError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JWKS cache — avoid fetching public keys on every request
# ---------------------------------------------------------------------------

_JWKS_CACHE: dict[str, dict] = {}       # issuer → {keys, fetched_at}
_JWKS_TTL   = 3600                       # re-fetch keys every hour


def _get_jwks(jwks_uri: str) -> list:
    """Fetch and cache JWKS keys from an IDP's well-known endpoint."""
    cached = _JWKS_CACHE.get(jwks_uri)
    if cached and time.time() - cached["fetched_at"] < _JWKS_TTL:
        return cached["keys"]

    logger.debug("Fetching JWKS from %s", jwks_uri)
    try:
        with urllib.request.urlopen(jwks_uri, timeout=5) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        raise ProxyAuthError(f"Failed to fetch JWKS from {jwks_uri}: {e}") from e

    _JWKS_CACHE[jwks_uri] = {"keys": data["keys"], "fetched_at": time.time()}
    return data["keys"]


# ---------------------------------------------------------------------------
# IDP detection — map issuer → JWKS URI
# ---------------------------------------------------------------------------

def _jwks_uri_for_issuer(issuer: str) -> str:
    """
    Derive the JWKS URI from the token's 'iss' claim.

    Cognito : https://cognito-idp.{region}.amazonaws.com/{pool_id}
              → {iss}/.well-known/jwks.json

    Okta    : https://{domain}.okta.com/oauth2/{server}
              → {iss}/v1/keys

    Generic OIDC (Auth0, Azure AD, etc.):
              → {iss}/.well-known/openid-configuration (discovery doc)
              → then read jwks_uri from discovery doc
    """
    issuer = issuer.rstrip("/")

    if "cognito-idp" in issuer:
        return f"{issuer}/.well-known/jwks.json"

    if "okta.com" in issuer:
        return f"{issuer}/v1/keys"

    # Generic OIDC discovery fallback
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    logger.debug("Unknown issuer, trying OIDC discovery: %s", discovery_url)
    try:
        with urllib.request.urlopen(discovery_url, timeout=5) as resp:
            config = json.loads(resp.read())
            return config["jwks_uri"]
    except Exception as e:
        raise ProxyAuthError(
            f"Cannot determine JWKS URI for issuer '{issuer}'. "
            f"Pass jwks_url explicitly to BedrockRuntimeClient."
        ) from e


# ---------------------------------------------------------------------------
# JWT decode helpers
# ---------------------------------------------------------------------------

def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload (base64). Does NOT verify signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ProxyAuthError("Invalid JWT — expected 3 parts")
        padding = "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(parts[1] + padding))
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        raise ProxyAuthError(f"Failed to decode JWT payload: {e}") from e


def _decode_jwt_header(token: str) -> dict:
    """Decode JWT header (base64). Does NOT verify signature."""
    try:
        parts = token.split(".")
        padding = "=" * (-len(parts[0]) % 4)
        return json.loads(base64.urlsafe_b64decode(parts[0] + padding))
    except Exception as e:
        raise ProxyAuthError(f"Failed to decode JWT header: {e}") from e


def _verify_signature(token: str, jwks_uri: str) -> dict:
    """
    Verify JWT RS256 signature using JWKS public keys.
    Requires: pip install PyJWT[crypto] cryptography
    Falls back to decode-only if PyJWT is not installed (POC mode).
    """
    try:
        import jwt as pyjwt
        from jwt import PyJWKClient

        jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = pyjwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},  # audience varies per app
        )
        logger.debug("JWT signature verified via JWKS: %s", jwks_uri)
        return payload
    except ImportError:
        logger.warning(
            "PyJWT not installed — skipping signature verification (POC mode). "
            "Run: pip install PyJWT[crypto] cryptography"
        )
        return _decode_jwt_payload(token)
    except Exception as e:
        raise ProxyAuthError(f"JWT signature verification failed: {e}") from e


# ---------------------------------------------------------------------------
def validate_and_extract(token: str, jwks_url: Optional[str] = None) -> dict:
    """
    Validate a JWT and extract identity claims.

    Works with tokens from any OIDC-compliant IDP:
      - Cognito (developers)
      - Okta (business users via Authorization Code flow)
      - Auth0, Azure AD, etc.

    Args:
        token    : The raw JWT string (ID token)
        jwks_url : Optional explicit JWKS URL. Auto-detected from 'iss' if omitted.

    Returns dict with:
        user_id   : 'sub' claim
        email     : 'email' claim
        username  : 'cognito:username' or 'preferred_username'
        issuer    : 'iss' claim — identifies which IDP issued the token
        idp       : 'cognito' | 'okta' | 'oidc'
        groups    : list of groups (Cognito groups or Okta groups claim)
    """
    if not token:
        raise ProxyAuthError("JWT is required — no token provided")

    payload = _decode_jwt_payload(token)

    # Check expiry first (fast, no network)
    exp = payload.get("exp")
    if exp is None:
        raise ProxyAuthError("JWT missing 'exp' claim")
    if time.time() > exp:
        raise ProxyAuthError("JWT has expired")

    # Determine IDP from issuer
    issuer = payload.get("iss", "")
    idp    = _detect_idp(issuer)

    # Verify signature if possible
    effective_jwks_url = jwks_url or _jwks_uri_for_issuer(issuer)
    payload = _verify_signature(token, effective_jwks_url)

    # Extract groups — field names differ between IDPs
    groups = (
        payload.get("cognito:groups", [])   # Cognito
        or payload.get("groups", [])        # Okta groups claim
    )

    # Extract identity — field names differ slightly between IDPs
    identity = {
        "user_id":  payload.get("sub", "unknown"),
        "email":    payload.get("email"),
        "username": (
            payload.get("cognito:username")      # Cognito
            or payload.get("preferred_username")  # Okta
            or payload.get("sub")
        ),
        "issuer":   issuer,
        "idp":      idp,
        "groups":   groups,
    }

    logger.debug(
        "Identity extracted: idp=%s user=%s email=%s groups=%s",
        idp, identity["user_id"], identity["email"], groups,
    )
    return identity


def _detect_idp(issuer: str) -> str:
    if "cognito-idp" in issuer:
        return "cognito"
    if "okta.com" in issuer:
        return "okta"
    return "oidc"


# ---------------------------------------------------------------------------
# TokenManager — caching + refresh
# ---------------------------------------------------------------------------

class TokenManager:
    """
    Manages JWT caching and silent refresh via a token_provider callable.

    token_provider : callable() -> str  returns a fresh JWT when called.
    jwks_url       : optional explicit JWKS URL (auto-detected if omitted).
    """

    def __init__(
        self,
        jwt: Optional[str] = None,
        token_provider: Optional[Callable] = None,
        jwks_url: Optional[str] = None,
    ):
        if not jwt and not token_provider:
            raise ProxyAuthError(
                "Either 'jwt' or 'token_provider' must be supplied to BedrockRuntimeClient"
            )
        self._token        = jwt
        self._token_provider = token_provider
        self._jwks_url     = jwks_url

    def get_valid_token(self) -> str:
        """Return a valid (non-expired) JWT, refreshing silently if needed."""
        if self._token:
            try:
                payload = _decode_jwt_payload(self._token)
                if time.time() < payload.get("exp", 0) - 60:
                    return self._token
            except ProxyAuthError:
                pass  # fall through to refresh

        if self._token_provider:
            logger.debug("Refreshing token via token_provider")
            self._token = self._token_provider()
            return self._token

        raise ProxyAuthError("JWT is expired and no token_provider was supplied for refresh")

    def get_identity(self) -> dict:
        """Return validated identity claims from the current token."""
        token = self.get_valid_token()
        return validate_and_extract(token, jwks_url=self._jwks_url)
