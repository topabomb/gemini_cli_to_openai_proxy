"""
凭据管理服务模块：
- 负责加载、持久化、刷新和轮换 Google OAuth2 凭据。
- 所有 I/O 操作都将改造为异步。
"""

import base64
import hashlib
import json
import logging
import random
import sys

logger = logging.getLogger(__name__)
import asyncio
import httpx
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

from ..core.config import (
    SettingsDict, CLIENT_ID, CLIENT_SECRET, SCOPES, CODE_ASSIST_ENDPOINT,
    HEALTH_CHECK_IDLE_THRESHOLD_SEC, HEALTH_CHECK_POSTPONE_INTERVAL_SEC
)
from ..core.types import CredentialStatus, ManagedCredential
from ..utils.sanitizer import sanitize_email, sanitize_project_id
from .state_tracker import SystemStateTracker
from .health_checker import HealthCheckService

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

def _derive_key(user_key: str) -> bytes:
    """从用户提供的字符串派生一个确定性的、URL安全的 Fernet 密钥。"""
    # 使用 SHA-256 生成一个32字节的哈希值
    digest = hashlib.sha256(user_key.encode('utf-8')).digest()
    # 使用 URL-safe Base64 编码，使其符合 Fernet 密钥格式
    return base64.urlsafe_b64encode(digest)

# ===== 主服务类 =====

class CredentialManager:
    """统一的凭据池管理服务。"""

    def __init__(
        self,
        settings: SettingsDict,
        http_client: httpx.AsyncClient,
        system_tracker: SystemStateTracker,
        health_checker: HealthCheckService,
    ):
        self.settings = settings
        self.http_client = http_client
        self.system_tracker = system_tracker
        self.health_checker = health_checker
        self.credentials: List[ManagedCredential] = []
        self.current_index = 0
        self.lock = asyncio.Lock()
        self.refresh_task: Optional[asyncio.Task] = None
        self.health_check_task: Optional[asyncio.Task] = None
        
        self.fernet: Optional[Fernet] = None
        if key := settings.get("credentials_encryption_key"):
            logger.info("[CredManager] Encryption key provided. Encrypting credentials file.")
            derived_key = _derive_key(key)
            self.fernet = Fernet(derived_key)

    def _read_file(self) -> List[Dict[str, Any]]:
        path = self.settings["credentials_file"]
        try:
            with open(path, "rb") as f:
                raw_data = f.read()
        except FileNotFoundError:
            return []
        except Exception as e:
            logger.error(f"[CredManager] Failed to read credentials file {path}: {e}")
            return []

        if not raw_data:
            return []

        # 如果提供了密钥，则必须能成功解密
        if self.fernet:
            try:
                decrypted_data = self.fernet.decrypt(raw_data)
            except InvalidToken:
                logger.critical("FATAL: Credentials file is encrypted, but the provided key is incorrect or the file is corrupted.")
                sys.exit(1)
            except Exception as e:
                logger.critical(f"FATAL: An unexpected error occurred during decryption: {e}")
                sys.exit(1)
        else:
            # 如果没有提供密钥，则直接使用原始数据
            decrypted_data = raw_data

        # 尝试解析JSON
        try:
            data = json.loads(decrypted_data)
            return [data] if isinstance(data, dict) else data
        except json.JSONDecodeError:
            # 如果没有提供密钥但JSON解析失败，很可能是因为文件是加密的
            if not self.fernet:
                logger.critical("FATAL: Failed to decode credentials file. It might be encrypted, but no encryption key was provided.")
                sys.exit(1)
            else:
                # 如果提供了密钥但解析失败，说明解密后的内容不是有效的JSON
                logger.critical("FATAL: Failed to decode credentials file after decryption. The file is likely corrupted.")
                sys.exit(1)

    def _write_file(self, items: List[Dict[str, Any]]):
        path = self.settings["credentials_file"]
        out: Any = items[0] if len(items) == 1 else items
        
        try:
            json_data = json.dumps(out, ensure_ascii=False, indent=2).encode('utf-8')
            
            final_data = json_data
            if self.fernet:
                final_data = self.fernet.encrypt(json_data)
            
            with open(path, "wb") as f:
                f.write(final_data)
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
        logger.debug(f"[CredManager] Updated metadata for {mc.id}: email={sanitize_email(email)}, project_id={sanitize_project_id(pid)}")

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
                    logger.info(f"[CredManager] Updating existing credential for {sanitize_email(new_email)} (id: {existing_cred.id}).")
                    existing_cred.credentials = new_creds
                    existing_cred.status = CredentialStatus.ACTIVE
                    existing_cred.failure_reason = None
                    existing_cred.failed_at = None
                    existing_cred.last_refreshed_at = datetime.now(timezone.utc)
                    self._persist_current_state()
                    return True, "credential_updated"

            logger.info(f"[CredManager] Adding new credential for {sanitize_email(new_email)}.")
            new_id = f"cred-{len(self.credentials)}"
            mc = ManagedCredential(id=new_id, credentials=new_creds, email=new_email, project_id=new_pid)
            self.credentials.append(mc)
            self._persist_current_state()
            return True, "credential_added"

    async def get_available(self) -> Optional[ManagedCredential]:
        async with self.lock:
            n = len(self.credentials)
            if n == 0: return None

            # 优先轮询完全可用的凭据
            for _ in range(n):
                c = self.credentials[self.current_index]
                self.current_index = (self.current_index + 1) % n
                if c.is_available():
                    c.mark_used()
                    return c
            
            # 如果没有完全可用的，则按优先级尝试懒汉式刷新
            # 优先级: 权限问题 > 用量问题 > 过期问题
            refresh_candidates = sorted(
                [c for c in self.credentials if c.credentials.refresh_token],
                key=lambda c: (
                    c.status != CredentialStatus.PERMISSION_DENIED, # False is sorted before True
                    c.status != CredentialStatus.RATE_LIMITED,
                    c.status != CredentialStatus.EXPIRED
                )
            )

            for c in refresh_candidates:
                if c.status in [CredentialStatus.PERMISSION_DENIED, CredentialStatus.RATE_LIMITED, CredentialStatus.EXPIRED]:
                    logger.info(f"[CredManager] On-demand refresh attempt for {sanitize_email(c.email)} in state {c.status}")
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
            logger.info(f"[CredManager] Refreshed credential for {sanitize_email(c.email)} successfully.")
            self._persist_current_state()
            return True
        except Exception as e:
            logger.error(f"[CredManager] Refresh failed for {sanitize_email(c.email)}: {e}")
            c.mark_as_permanent_error(f"error_during_refresh,{str(e)}")
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
                logger.debug("[CredManager] Running periodic credential recovery and refresh check...")
                async with self.lock:
                    for c in self.credentials:
                        if not c.credentials.refresh_token:
                            continue

                        # 1. 优先处理需要立即刷新的状态
                        if c.status in [CredentialStatus.PERMISSION_DENIED]:
                            logger.info(f"[CredManager] Proactively refreshing credential for {sanitize_email(c.email)} due to status: {c.status}")
                            await self._refresh_credential(c)
                            continue # 处理完一个就进入下一个循环，避免重复操作

                        # 2. 处理已度过冷静期的速率限制状态
                        if c.status == CredentialStatus.RATE_LIMITED and c.rate_limited_until and datetime.now(timezone.utc) > c.rate_limited_until:
                            logger.info(f"[CredManager] Credential for {sanitize_email(c.email)} has recovered from rate limit, attempting refresh.")
                            await self._refresh_credential(c)
                            continue
                        
                        # 3. 处理即将过期的活跃凭据
                        if c.status == CredentialStatus.ACTIVE and c.credentials.expiry:
                            expiry_utc = c.credentials.expiry if c.credentials.expiry.tzinfo is not None else c.credentials.expiry.replace(tzinfo=timezone.utc)
                            if expiry_utc < datetime.now(timezone.utc) + timedelta(minutes=10):
                                logger.info(f"[CredManager] Proactively refreshing near-expiry credential for {sanitize_email(c.email)}.")
                                await self._refresh_credential(c)

                base_interval = 300
                # 在基础间隔的 50% 到 100% 之间随机选择延迟时间
                delay = base_interval * random.uniform(0.5, 1.0)
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                logger.info("[CredManager] Refresh loop cancelled.")
                break
            except Exception as e:
                logger.error(f"[CredManager] Refresh loop error: {e}")
                await asyncio.sleep(60)

    async def _health_check_loop(self):
        """
        后台健康检查循环，主动发现“亚健康”凭据。
        """
        while True:
            try:
                # 1. 检查系统是否繁忙
                if self.system_tracker.active_requests_count > 0:
                    postpone_duration = HEALTH_CHECK_POSTPONE_INTERVAL_SEC + random.uniform(-5, 5)
                    logger.debug(f"System is busy. Postponing health check for {postpone_duration:.2f} seconds.")
                    await asyncio.sleep(postpone_duration)
                    continue

                async with self.lock:
                    # 2. 筛选出需要检查的凭据
                    #   - 状态为 ACTIVE
                    #   - 有效的 refresh_token
                    #   - 距离上次使用时间超过阈值
                    now = datetime.now(timezone.utc)
                    idle_threshold = timedelta(seconds=HEALTH_CHECK_IDLE_THRESHOLD_SEC)
                    
                    candidates = [
                        c for c in self.credentials
                        if c.status == CredentialStatus.ACTIVE and 
                           c.credentials.refresh_token and
                           (now - c.last_used_at) > idle_threshold
                    ]

                    if not candidates:
                        # 没有需要检查的凭据，短暂休眠后继续
                        await asyncio.sleep(60)
                        continue

                    # 3. 从候选者中选择最久未使用的那个
                    target_cred = min(candidates, key=lambda c: c.last_used_at)
                    
                    logger.info(f"Performing health check on idle credential: {target_cred.log_safe_id}")
                    
                    # 4. 执行健康检查
                    is_healthy = await self.health_checker.check(target_cred)
                    
                    if not is_healthy:
                        target_cred.mark_suspected()
                    else:
                        # 如果检查通过，可以认为它“被使用”了一次，以更新其 last_used_at 时间戳
                        target_cred.mark_used()

                # 5. 随机化休眠以避免惊群效应
                await asyncio.sleep(HEALTH_CHECK_POSTPONE_INTERVAL_SEC * random.uniform(0.8, 1.2))

            except asyncio.CancelledError:
                logger.info("[CredManager] Health check loop cancelled.")
                break
            except Exception as e:
                logger.error(f"[CredManager] Health check loop error: {e}", exc_info=True)
                await asyncio.sleep(60) # 发生未知错误时，等待较长时间

    def start_background_tasks(self):
        if not (self.refresh_task and not self.refresh_task.done()):
            self.refresh_task = asyncio.create_task(self._refresh_loop())
            logger.info("[CredManager] Background credential refresh task started.")
        
        if not (self.health_check_task and not self.health_check_task.done()):
            self.health_check_task = asyncio.create_task(self._health_check_loop())
            logger.info("[CredManager] Background health check task started.")

    def stop_background_tasks(self):
        if self.refresh_task and not self.refresh_task.done():
            self.refresh_task.cancel()
            logger.info("[CredManager] Background credential refresh task stopped.")
        
        if self.health_check_task and not self.health_check_task.done():
            self.health_check_task.cancel()
            logger.info("[CredManager] Background health check task stopped.")

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
                "email": sanitize_email(c.email),
                "project_id": sanitize_project_id(c.project_id),
                "status": c.status,
                "is_available": c.is_available(),
                "expiry": expiry_str,
                "usage_count": c.usage_count,
                "created_at": format_datetime(c.created_at),
                "last_used_at": format_datetime(c.last_used_at),
                "last_refreshed_at": format_datetime(c.last_refreshed_at),
                "rate_limited_until": format_datetime(c.rate_limited_until),
                "failed_at": format_datetime(c.failed_at),
                "failure_reason": c.failure_reason,
            })
        return details
