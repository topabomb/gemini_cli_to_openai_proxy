"""
凭据管理服务模块：
- 负责加载、持久化、刷新和轮换 Google OAuth2 凭据。
- 所有 I/O 操作都将改造为异步。
"""

import json
import logging
import random

logger = logging.getLogger(__name__)
import asyncio
import httpx
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

from ..core.config import SettingsDict, CLIENT_ID, CLIENT_SECRET, SCOPES, CODE_ASSIST_ENDPOINT

# ===== 辅助函数 =====

def _ms_to_datetime(ms: int) -> datetime:
    """毫秒时间戳转 UTC datetime。"""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)

def _datetime_to_ms(dt: datetime) -> int:
    """UTC datetime 转毫秒时间戳（容忍 naive，按 UTC 处理）。"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)

def _build_credentials_from_simple(simple: Dict[str, Any]) -> Credentials:
    """由四字段构造 Google Credentials。"""
    info = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "token": simple.get("access_token"),
        "refresh_token": simple.get("refresh_token"),
        "token_uri": "https://oauth2.googleapis.com/token",
        "scopes": SCOPES,
    }
    creds = Credentials.from_authorized_user_info(info, SCOPES)
    if expiry_ms := simple.get("expiry_date"):
        creds.expiry = _ms_to_datetime(int(expiry_ms))
    return creds

def _credentials_to_simple(creds: Credentials) -> Dict[str, Any]:
    """将 Credentials 转为四字段。"""
    expiry_ms = _datetime_to_ms(creds.expiry) if creds.expiry else None
    return {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_type": "Bearer",
        "expiry_date": expiry_ms,
    }

# ===== 数据类定义 =====

class CredentialStatus:
    ACTIVE = "active"
    EXPIRED = "expired"
    REFRESHING = "refreshing"
    EXHAUSTED = "exhausted"
    ERROR = "error"

@dataclass
class ManagedCredential:
    """封装一个 Google OAuth2 凭据及其相关的元数据和状态。"""
    id: str
    credentials: Credentials
    project_id: Optional[str] = None
    email: Optional[str] = None
    status: str = CredentialStatus.ACTIVE
    
    # 时间戳
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_refreshed_at: Optional[datetime] = None
    exhausted_until: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    
    # 统计与状态
    usage_count: int = 0
    failure_reason: Optional[str] = None

    def is_available(self) -> bool:
        """检查凭据当前是否可用。"""
        if self.status in [CredentialStatus.EXPIRED, CredentialStatus.ERROR, CredentialStatus.REFRESHING]:
            return False
        if self.status == CredentialStatus.EXHAUSTED and self.exhausted_until and datetime.now(timezone.utc) < self.exhausted_until:
            return False
        
        is_expired = False
        if self.credentials.expiry:
            expiry_utc = self.credentials.expiry if self.credentials.expiry.tzinfo is not None else self.credentials.expiry.replace(tzinfo=timezone.utc)
            is_expired = expiry_utc < datetime.now(timezone.utc)

        if is_expired:
            self.status = CredentialStatus.EXPIRED
            return False
        return True

    def mark_used(self):
        self.last_used_at = datetime.now(timezone.utc)
        self.usage_count += 1

    def mark_exhausted(self, minutes: int = 30):
        self.status = CredentialStatus.EXHAUSTED
        self.exhausted_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)

    def mark_failed(self, reason: str):
        """根据失败原因更新凭据状态。"""
        if reason == "429":
            self.mark_exhausted()
        else:
            self.status = CredentialStatus.ERROR
            self.failure_reason = f"HTTP Error {reason}"
            self.failed_at = datetime.now(timezone.utc)

# ===== 主服务类 =====

class CredentialManager:
    """统一的凭据池管理服务。"""

    def __init__(self, settings: SettingsDict, http_client: httpx.AsyncClient):
        self.settings = settings
        self.http_client = http_client
        self.credentials: List[ManagedCredential] = []
        self.current_index = 0
        self.lock = asyncio.Lock()
        self.refresh_task: Optional[asyncio.Task] = None

    def _read_file(self) -> List[Dict[str, Any]]:
        path = self.settings["credentials_file"]
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [data] if isinstance(data, dict) else data
        except FileNotFoundError:
            return []
        except Exception as e:
            logger.error(f"[CredManager] Failed to read credentials file {path}: {e}")
            return []

    def _write_file(self, items: List[Dict[str, Any]]):
        path = self.settings["credentials_file"]
        out: Any = items[0] if len(items) == 1 else items
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"[CredManager] Failed to write credentials file {path}: {e}")

    async def _get_email_from_credentials(self, creds: Credentials) -> Optional[str]:
        headers = {"Authorization": f"Bearer {creds.token}"}
        try:
            resp = await self.http_client.get("https://openidconnect.googleapis.com/v1/userinfo", headers=headers, timeout=10)
            if resp.is_success:
                return resp.json().get("email")
        except Exception as e:
            logger.warning(f"[CredManager] Failed to get email via userinfo endpoint: {e}")
        return None

    async def _discover_project_id(self, creds: Credentials) -> Optional[str]:
        headers = {"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"}
        payload = {"metadata": {}}
        try:
            resp = await self.http_client.post(f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist", json=payload, headers=headers, timeout=20)
            resp.raise_for_status()
            return resp.json().get("cloudaicompanionProject")
        except Exception as e:
            logger.warning(f"[CredManager] Failed to discover project_id via API: {e}")
            return None

    async def load_credentials(self):
        simple_items = self._read_file()
        logger.info(f"[CredManager] Loading {len(simple_items)} credentials from file.")
        
        async with self.lock:
            self.credentials = []
            for idx, item in enumerate(simple_items):
                try:
                    creds = _build_credentials_from_simple(item)
                    
                    is_expired = False
                    if creds.expiry:
                        expiry_utc = creds.expiry if creds.expiry.tzinfo is not None else creds.expiry.replace(tzinfo=timezone.utc)
                        is_expired = expiry_utc < datetime.now(timezone.utc)

                    if is_expired and creds.refresh_token:
                        logger.info(f"[CredManager] Credential {idx} expired, attempting refresh on load.")
                        await self._refresh_credential_object(creds)
                    
                    mc = ManagedCredential(id=f"cred-{idx}", credentials=creds)
                    await self._update_managed_credential_metadata(mc)
                    self.credentials.append(mc)
                except Exception as e:
                    logger.warning(f"[CredManager] Skipping invalid credential item {idx}: {e}")
        
        logger.info(f"[CredManager] Loaded {len(self.credentials)} valid credentials.")
        if any(c.status == CredentialStatus.ACTIVE for c in self.credentials):
            self._persist_current_state()

    async def _update_managed_credential_metadata(self, mc: ManagedCredential):
        email = await self._get_email_from_credentials(mc.credentials)
        if not email:
            mc.status = CredentialStatus.ERROR
            mc.failure_reason = "Failed to get email"
            mc.failed_at = datetime.now(timezone.utc)
            logger.warning(f"[CredManager] Credential {mc.id} missing email, marked as invalid.")
            return

        mc.email = email
        pid = self.settings["project_id_map"].get(email)
        if not pid:
            pid = await self._discover_project_id(mc.credentials)
        
        if not pid:
            mc.status = CredentialStatus.ERROR
            mc.failure_reason = "Failed to discover project_id"
            mc.failed_at = datetime.now(timezone.utc)
            logger.warning(f"[CredManager] Credential {mc.id} for {email} missing project_id, marked as invalid.")
            return
        
        mc.project_id = pid
        logger.debug(f"[CredManager] Updated metadata for {mc.id}: email={email}, project_id={pid}")

    async def add_or_update_credential(self, new_creds: Credentials) -> Tuple[bool, str]:
        """
        根据 email 和 project_id 添加或更新一个凭据。
        如果已存在，则更新；如果不存在，则添加。
        """
        if not new_creds.refresh_token:
            return False, "missing_refresh_token"

        new_email = await self._get_email_from_credentials(new_creds)
        if not new_email:
            return False, "failed_to_get_email"
            
        new_pid = self.settings["project_id_map"].get(new_email) or await self._discover_project_id(new_creds)
        if not new_pid:
            return False, "failed_to_discover_project_id"

        async with self.lock:
            for existing_cred in self.credentials:
                if existing_cred.email == new_email and existing_cred.project_id == new_pid:
                    logger.info(f"[CredManager] Updating existing credential for {new_email} (id: {existing_cred.id}).")
                    existing_cred.credentials = new_creds
                    existing_cred.status = CredentialStatus.ACTIVE
                    existing_cred.failure_reason = None
                    existing_cred.failed_at = None
                    existing_cred.last_refreshed_at = datetime.now(timezone.utc)
                    self._persist_current_state()
                    return True, "credential_updated"

            logger.info(f"[CredManager] Adding new credential for {new_email}.")
            new_id = f"cred-{len(self.credentials)}"
            mc = ManagedCredential(id=new_id, credentials=new_creds, email=new_email, project_id=new_pid)
            self.credentials.append(mc)
            self._persist_current_state()
            return True, "credential_added"

    async def get_available(self) -> Optional[ManagedCredential]:
        async with self.lock:
            n = len(self.credentials)
            if n == 0: return None

            for _ in range(n):
                c = self.credentials[self.current_index]
                self.current_index = (self.current_index + 1) % n
                if c.is_available():
                    c.mark_used()
                    return c
            
            for c in self.credentials:
                if c.status == CredentialStatus.EXPIRED and c.credentials.refresh_token:
                    if await self._refresh_credential(c):
                        c.mark_used()
                        return c
            return None

    async def _refresh_credential(self, c: ManagedCredential) -> bool:
        c.status = CredentialStatus.REFRESHING
        try:
            await self._refresh_credential_object(c.credentials)
            c.status = CredentialStatus.ACTIVE
            c.last_refreshed_at = datetime.now(timezone.utc)
            c.failure_reason = None
            logger.info(f"[CredManager] Refreshed credential for {c.email} successfully.")
            self._persist_current_state()
            return True
        except Exception as e:
            logger.error(f"[CredManager] Refresh failed for {c.email}: {e}")
            c.status = CredentialStatus.ERROR
            c.failed_at = datetime.now(timezone.utc)
            c.failure_reason = str(e)
            return False

    async def _refresh_credential_object(self, creds: Credentials):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, creds.refresh, GoogleAuthRequest())

    def _persist_current_state(self):
        items = [_credentials_to_simple(c.credentials) for c in self.credentials]
        self._write_file(items)
        logger.debug("[CredManager] Persisted current credentials state to file.")

    async def _refresh_loop(self):
        while True:
            try:
                logger.debug("[CredManager] Running periodic credential refresh check...")
                async with self.lock:
                    for c in self.credentials:
                        if c.credentials.expiry:
                            expiry_utc = c.credentials.expiry if c.credentials.expiry.tzinfo is not None else c.credentials.expiry.replace(tzinfo=timezone.utc)
                            if expiry_utc < datetime.now(timezone.utc) + timedelta(minutes=10):
                                if c.credentials.refresh_token and c.status == CredentialStatus.ACTIVE:
                                    await self._refresh_credential(c)
                await asyncio.sleep(300)
            except asyncio.CancelledError:
                logger.info("[CredManager] Refresh loop cancelled.")
                break
            except Exception as e:
                logger.error(f"[CredManager] Refresh loop error: {e}")
                await asyncio.sleep(60)

    def start_refresh_task(self):
        if self.refresh_task and not self.refresh_task.done():
            return
        self.refresh_task = asyncio.create_task(self._refresh_loop())
        logger.info("[CredManager] Background credential refresh task started.")

    def stop_refresh_task(self):
        if self.refresh_task and not self.refresh_task.done():
            self.refresh_task.cancel()
            logger.info("[CredManager] Background credential refresh task stopped.")

    def get_all_credential_details(self) -> List[Dict[str, Any]]:
        details = []
        for c in self.credentials:
            def format_datetime(dt: Optional[datetime]) -> Optional[str]:
                return dt.isoformat() if dt else None

            expiry_str = "N/A"
            if c.credentials.expiry:
                try:
                    local_expiry = c.credentials.expiry.astimezone()
                    expiry_str = local_expiry.strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    expiry_str = str(c.credentials.expiry)
            
            details.append({
                "id": c.id,
                "email": c.email,
                "project_id": c.project_id,
                "status": c.status,
                "is_available": c.is_available(),
                "expiry": expiry_str,
                "usage_count": c.usage_count,
                "created_at": format_datetime(c.created_at),
                "last_used_at": format_datetime(c.last_used_at),
                "last_refreshed_at": format_datetime(c.last_refreshed_at),
                "exhausted_until": format_datetime(c.exhausted_until),
                "failed_at": format_datetime(c.failed_at),
                "failure_reason": c.failure_reason,
            })
        return details
