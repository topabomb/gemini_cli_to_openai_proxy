"""
This module provides typed utilities for handling credential serialization
and project ID discovery, shared between the server and the client.
"""
import logging
from typing_extensions import Any, Dict, List, Optional, TypedDict
from google.oauth2.credentials import Credentials
import httpx
from pydantic import BaseModel

from ..core.config import CLIENT_ID, CLIENT_SECRET, SCOPES, CODE_ASSIST_ENDPOINT
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ===== Data Models =====

class SimpleCredential(TypedDict):
    """A typed dictionary representing the essential, serializable fields of a credential."""
    access_token: Optional[str]
    refresh_token: Optional[str]
    token_type: str
    expiry_date: Optional[int]  # Milliseconds
    scopes: List[str]

class AddCredentialRequest(BaseModel):
    """Pydantic model for the request to add a new credential."""
    credential: SimpleCredential
    project_id: Optional[str] = None

# ===== Serialization/Deserialization =====

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

# ===== Project ID Discovery =====

async def get_email_from_credentials(creds: Credentials, http_client: httpx.AsyncClient) -> Optional[str]:
    """Fetches the user's email address using the provided credentials."""
    headers = {"Authorization": f"Bearer {creds.token}"}
    try:
        resp = await http_client.get("https://openidconnect.googleapis.com/v1/userinfo", headers=headers, timeout=10)
        if resp.is_success:
            return resp.json().get("email")
    except Exception as e:
        logger.warning(f"Failed to get email via userinfo endpoint: {e}")
    return None

async def discover_project_id(creds: Credentials, http_client: httpx.AsyncClient) -> Optional[str]:
    """Discovers the GCP project ID associated with the credentials."""
    headers = {"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"}
    payload = {"metadata": {}}
    try:
        resp = await http_client.post(f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist", json=payload, headers=headers, timeout=20)
        resp.raise_for_status()
        return resp.json().get("cloudaicompanionProject")
    except Exception as e:
        logger.warning(f"Failed to discover project_id via API: {e}")
        return None

async def determine_project_id(
    creds: Credentials,
    project_id_map: Dict[str, str],
    http_client: httpx.AsyncClient
) -> Optional[str]:
    """
    Determines the project ID using a priority-based approach:
    1. Check the provided project_id_map.
    2. Fall back to discovering via API call.
    """
    email = await get_email_from_credentials(creds, http_client)
    if not email:
        logger.warning("Could not determine project ID because email could not be fetched.")
        return None

    # 1. Check map first
    if project_id := project_id_map.get(email):
        logger.info(f"Found project ID '{project_id}' in config map for email '{email}'.")
        return project_id

    # 2. Fall back to API discovery
    logger.info(f"Project ID for '{email}' not in config map, attempting API discovery.")
    return await discover_project_id(creds, http_client)
