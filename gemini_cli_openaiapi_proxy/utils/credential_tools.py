"""
This module provides typed utilities for handling credential serialization,
shared between the server and the client.
"""
import logging
from typing import Any, Dict, List, Optional, TypedDict
from google.oauth2.credentials import Credentials
from ..core.config import CLIENT_ID, CLIENT_SECRET, SCOPES
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class SimpleCredential(TypedDict):
    """A typed dictionary representing the essential, serializable fields of a credential."""
    access_token: Optional[str]
    refresh_token: Optional[str]
    token_type: str
    expiry_date: Optional[int]  # Milliseconds
    scopes: List[str]

def _datetime_to_ms(dt: datetime) -> int:
    """Converts a UTC datetime object to milliseconds since the epoch."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)

def _ms_to_datetime(ms: int) -> datetime:
    """Converts milliseconds since the epoch to a UTC datetime object."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)

def credentials_to_simple(creds: Credentials) -> SimpleCredential:
    """Serializes a Credentials object into a SimpleCredential typed dict."""
    expiry_ms = _datetime_to_ms(creds.expiry) if creds.expiry else None
    simple: SimpleCredential = {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_type": "Bearer",
        "expiry_date": expiry_ms,
        "scopes": creds.scopes or [],
    }
    return simple

def build_credentials_from_simple(simple: SimpleCredential) -> Credentials:
    """Builds a Credentials object from a simple dictionary."""
    scopes_to_use = simple.get("scopes")
    if not scopes_to_use:
        scopes_to_use = SCOPES
        logger.debug("Building credential. Scopes not in file, falling back to constant: %s", scopes_to_use)

    info = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "token": simple.get("access_token"),
        "refresh_token": simple.get("refresh_token"),
        "token_uri": "https://oauth2.googleapis.com/token",
        "scopes": scopes_to_use,
    }
    creds = Credentials.from_authorized_user_info(info, scopes_to_use)
    if expiry_ms := simple.get("expiry_date"):
        creds.expiry = _ms_to_datetime(int(expiry_ms))
    return creds
