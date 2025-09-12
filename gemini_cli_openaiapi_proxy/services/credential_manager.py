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
from typing import Any, Dict, List, Optional, Tuple,cast

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

from ..core.config import (
    SettingsDict, CLIENT_ID, CLIENT_SECRET, SCOPES, CODE_ASSIST_ENDPOINT,
    HEALTH_CHECK_IDLE_THRESHOLD_SEC, HEALTH_CHECK_POSTPONE_INTERVAL_SEC
)
from ..core.types import CredentialStatus, ManagedCredential
from ..utils.sanitizer import sanitize_email, sanitize_project_id
from ..utils.credential_tools import SimpleCredential, build_credentials_from_simple, credentials_to_simple, get_client_metadata, get_email_from_credentials,determine_project_id, loadCodeAssist
from .state_tracker import SystemStateTracker
from .health_checker import HealthCheckService

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

    def _read_file(self) -> List[SimpleCredential]:
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
            return [cast(SimpleCredential, data)] if isinstance(data, dict) else data
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
        out: Any = items if len(items) == 1 else items
        
        try:
            json_data = json.dumps(out, ensure_ascii=False, indent=2).encode('utf-8')
            
            final_data = json_data
            if self.fernet:
                final_data = self.fernet.encrypt(json_data)
            
            with open(path, "wb") as f:
                f.write(final_data)
        except Exception as e:
            logger.error(f"[CredManager] Failed to write credentials file {path}: {e}")

    async def load_credentials(self):
        simple_items = self._read_file()
        logger.info(f"[CredManager] Loading {len(simple_items)} credentials from file.")
        
        async with self.lock:
            self.credentials = []
            for idx, item in enumerate(simple_items):
                try:
                    creds = build_credentials_from_simple(item)
                    
                    is_expired = False
                    if creds.expiry:
                        expiry_utc = creds.expiry if creds.expiry.tzinfo is not None else creds.expiry.replace(tzinfo=timezone.utc)
                        is_expired = expiry_utc < datetime.now(timezone.utc)

                    if is_expired and creds.refresh_token:
                        logger.info(f"[CredManager] Credential {idx} expired, attempting refresh on load.")
                        await self._refresh_credential_object(creds)
                    
                    # 如果文件中存在，则预先填充元数据
                    project_id_from_file = item.get("project_id")
                    mc = ManagedCredential(id=f"cred-{idx}", credentials=creds, project_id=project_id_from_file)
                    
                    # 这个方法现在会更智能，如果元数据已存在，则避免网络调用
                    await self._update_managed_credential_metadata(mc)
                    
                    # 用户上船
                    onboard_success = await self._onboard_user(mc)
                    if not onboard_success:
                        # _onboard_user 内部会记录详细错误，这里只记录跳过
                        logger.warning(f"[CredManager] Skipping credential {mc.log_safe_id} due to onboarding failure.")
                        continue

                    self.credentials.append(mc)
                except Exception as e:
                    logger.warning(f"[CredManager] Skipping invalid credential item {idx}: {e}")
        
        logger.info(f"[CredManager] Loaded {len(self.credentials)} valid credentials.")
        if any(c.status == CredentialStatus.ACTIVE for c in self.credentials):
            self._persist_current_state()
    async def _onboard_user(self, mc: ManagedCredential) -> bool:
        """
        为用户激活 Code Assist 服务（“上船”）。
        包含重试和超时逻辑。
        """
        sanitized_email = sanitize_email(mc.email)
        try:
            info = await loadCodeAssist(mc.credentials, self.http_client)
            
            if info.get("currentTier"):
                logger.info(f"[Onboarding] User {sanitized_email} is already onboarded.")
                return True

            tier = info.get("currentTier")
            if not tier:
                for t in info.get("allowedTiers", []):
                    if t.get("isDefault"):
                        tier = t
                        break
                if not tier:
                    tier = {"id": "legacy-tier", "userDefinedCloudaicompanionProject": True}
            
            logger.info(f"[Onboarding] Attempting to onboard user {sanitized_email} with tier '{tier.get('id')}'.")

            payload = {
                "tierId": tier.get("id"),
                "cloudaicompanionProject": mc.project_id,
                "metadata": get_client_metadata(mc.project_id)
            }

            max_retries = 30  # 最多轮询30次，约30秒
            for i in range(max_retries):
                resp = await self.http_client.post(
                    f"{CODE_ASSIST_ENDPOINT}/v1internal:onboardUser",
                    json=payload,
                    headers={"Authorization": f"Bearer {mc.credentials.token}", "Content-Type": "application/json"},
                    timeout=10
                )

                if resp.status_code == 200:
                    response_data = resp.json()
                    if response_data.get("done"):
                        logger.info(f"[Onboarding] User {sanitized_email} onboarding successful.")
                        return True
                    
                    logger.debug(f"[Onboarding] Waiting for user {sanitized_email}, attempt {i + 1}/{max_retries}...")
                    await asyncio.sleep(1)
                else:
                    logger.error(
                        f"[Onboarding] Failed for {sanitized_email}. Status: {resp.status_code}, Response: {resp.text}"
                    )
                    return False
            
            logger.error(f"[Onboarding] Timed out for user {sanitized_email} after {max_retries} attempts.")
            return False

        except Exception as e:
            logger.error(f"[Onboarding] Exception for {sanitized_email}: {e}", exc_info=True)
            return False
        

    async def _update_managed_credential_metadata(self, mc: ManagedCredential):
        """
        确保一个 ManagedCredential 对象的 email 和 project_id 被填充。
        如果数据已存在，此方法会避免不必要的网络调用。
        """
        # 1. 如果 email 缺失，则填充
        if not mc.email:
            email = await get_email_from_credentials(mc.credentials, self.http_client)
            if not email:
                mc.mark_as_permanent_error("Failed to get email")
                logger.warning(f"[CredManager] Credential {mc.id} missing email, marked as invalid.")
                return
            mc.email = email
        
        sanitized_email = sanitize_email(mc.email)

        # 2. 如果 project_id 缺失，则填充
        if not mc.project_id:
            logger.info(f"[CredManager] Project ID for {sanitized_email} not found in file, determining now...")
            pid=await determine_project_id(mc.credentials, self.settings.get("project_id_map", {}), self.http_client)
            
            if not pid:
                mc.mark_as_permanent_error("Failed to discover project_id")
                logger.warning(f"[CredManager] Credential {mc.id} for {sanitized_email} missing project_id, marked as invalid.")
                return
            mc.project_id = pid
        
        sanitized_pid = sanitize_project_id(mc.project_id)
        logger.debug(f"[CredManager] Ensured metadata for {mc.id}: email={sanitized_email}, project_id={sanitized_pid}")

    async def add_or_update_credential(
        self, new_creds: Credentials, project_id_override: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        添加或更新一个凭据。
        项目ID按以下优先级确定：
        1. `project_id_override` 参数。
        2. 配置文件中的 `project_id_map`。
        3. 通过 API 自动发现。
        """
        logger.debug(f"[CredManager] Received new credential with scopes: {new_creds.scopes}")
        if not new_creds.refresh_token:
            logger.warning("[CredManager] Add/Update failed: credential is missing refresh_token.")
            return False, "missing_refresh_token"

        new_email = await get_email_from_credentials(new_creds, self.http_client)
        if not new_email:
            logger.warning("[CredManager] Add/Update failed: could not get email from new credential.")
            return False, "failed_to_get_email"
        
        sanitized_email = sanitize_email(new_email)
        logger.debug(f"[CredManager] Processing credential for user: {sanitized_email}")

        # 确定项目ID
        final_project_id = project_id_override
        if not final_project_id:
            final_project_id=await determine_project_id(new_creds,self.settings.get("project_id_map",{}),self.http_client)
        
        if not final_project_id:
            logger.warning(f"[CredManager] Add/Update for {sanitized_email} failed: could not determine project_id.")
            return False, "failed_to_determine_project_id"
        
        
        
        sanitized_pid = sanitize_project_id(final_project_id)
        logger.debug(f"[CredManager] Using project_id '{sanitized_pid}' for {sanitized_email}.")


        for existing_cred in self.credentials:
            if existing_cred.email == new_email and (existing_cred.project_id is None or existing_cred.project_id == final_project_id):
                logger.info(
                    f"[CredManager] Credential for {sanitized_email} with project_id '{sanitized_pid}' "
                    f"was updated successfully (id: {existing_cred.id})."
                )
                existing_cred.credentials = new_creds
                existing_cred.project_id = final_project_id
                existing_cred.status = CredentialStatus.ACTIVE
                existing_cred.failure_reason = None
                existing_cred.failed_at = None
                existing_cred.last_refreshed_at = datetime.now(timezone.utc)
                self._persist_current_state()
                return True, "credential_updated"

        new_id = f"cred-{len(self.credentials)}"
        mc = ManagedCredential(id=new_id, credentials=new_creds, email=new_email, project_id=final_project_id)
        
        # 用户上船
        onboard_success = await self._onboard_user(mc)
        if not onboard_success:
            logger.warning(f"[CredManager] Failed to add credential for {sanitized_email} due to onboarding failure.")
            return False, "onboarding_failed"

        self.credentials.append(mc)
        logger.info(
            f"[CredManager] Credential for {sanitized_email} with project_id '{sanitized_pid}' "
            f"was added successfully (id: {new_id})."
        )
        self._persist_current_state()
        return True, "credential_added"

    async def get_available(self) -> Optional[ManagedCredential]:
        # 允许多次尝试，以覆盖一次按需刷新的场景
        for _ in range(len(self.credentials) + 2):
            refresh_candidate = None
            
            # 步骤 1: 在锁内快速查找可用凭据或刷新候选项
            async with self.lock:
                n = len(self.credentials)
                if n == 0:
                    return None

                # 优先轮询完全可用的凭据
                for _ in range(n):
                    c = self.credentials[self.current_index]
                    self.current_index = (self.current_index + 1) % n
                    if c.is_available():
                        c.mark_used()
                        return c
                
                # 如果没有立即可用的，则寻找最佳的刷新候选项
                candidates = sorted(
                    [c for c in self.credentials if c.credentials.refresh_token and c.status != CredentialStatus.REFRESHING],
                    key=lambda c: (
                        c.status != CredentialStatus.PERMISSION_DENIED,
                        c.status != CredentialStatus.RATE_LIMITED,
                        c.status != CredentialStatus.EXPIRED
                    )
                )
                if candidates:
                    refresh_candidate = candidates[0]

            # 步骤 2: 在锁外执行耗时的刷新操作
            if refresh_candidate:
                logger.info(f"[CredManager] On-demand refresh attempt for {refresh_candidate.log_safe_id} in state {refresh_candidate.status}")
                refreshed = await self._refresh_credential(refresh_candidate)
                if refreshed:
                    # 刷新成功后，循环将再次尝试获取凭据
                    continue
            
            # 如果没有刷新候选项，或者刷新失败，则退出循环
            break
            
        return None

    async def _refresh_credential(self, c: ManagedCredential) -> bool:
        # 在锁外执行网络IO
        try:
            # 标记为刷新中，但不立即获取锁
            async with self.lock:
                c.status = CredentialStatus.REFRESHING
            
            logger.debug(f"[CredManager] Attempting to refresh {c.log_safe_id} with scopes: {c.credentials.scopes}")
            await self._refresh_credential_object(c.credentials)
            
            # 成功后，获取锁以更新状态并持久化
            async with self.lock:
                c.mark_healthy(f"Successfully refreshed for {c.log_safe_id}")
                c.last_refreshed_at = datetime.now(timezone.utc)
                self._persist_current_state()
            
            logger.info(f"[CredManager] Refreshed credential for {c.log_safe_id} successfully.")
            return True
            
        except Exception as e:
            logger.error(f"[CredManager] Refresh failed for {c.log_safe_id}: {e}")
            # 失败后，获取锁以记录错误状态
            async with self.lock:
                c.mark_as_permanent_error(f"error_during_refresh,{str(e)}")
            return False

    async def _refresh_credential_object(self, creds: Credentials):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, creds.refresh, GoogleAuthRequest())

    def _persist_current_state(self):
        items_to_persist: List[SimpleCredential] = []
        for c in self.credentials:
            simple_cred = credentials_to_simple(c.credentials,c.project_id)
            items_to_persist.append(simple_cred)
        
        # 为了满足 _write_file 的类型检查，进行类型转换
        self._write_file(cast(List[Dict[str, Any]], items_to_persist))
        logger.debug("[CredManager] Persisted current credentials state to file.")

    def _should_proactively_refresh(self, c: ManagedCredential) -> bool:
        """判断一个凭据是否应该由后台循环进行主动刷新。"""
        now = datetime.now(timezone.utc)

        if not c.credentials.refresh_token:
            return False

        # 1. 安全锁：不要触碰最近活跃过的凭据。
        if c.last_used_at and (now - c.last_used_at) < timedelta(minutes=30):
            return False

        # 2. 恢复性刷新：用于从速率限制中恢复的凭据。
        is_rate_limited_and_recovered = (
            c.status == CredentialStatus.RATE_LIMITED and
            c.rate_limited_until and now > c.rate_limited_until
        )
        if is_rate_limited_and_recovered:
            return True

        # 3. 预防性/修复性刷新：用于即将过期或已过期的凭据。
        is_in_expiry_check_scope = c.status in [
            CredentialStatus.ACTIVE,
            CredentialStatus.SUSPECTED,
            CredentialStatus.EXPIRED
        ]
        if is_in_expiry_check_scope and c.credentials.expiry:
            random_expiry_window = timedelta(minutes=random.randint(1, 10))
            # 如果凭据将在随机窗口内过期（这也包含了已经过期的情况），则刷新。
            if c.credentials.expiry.replace(tzinfo=timezone.utc) < now + random_expiry_window:
                return True
        
        return False

    async def _refresh_loop(self):
        while True:
            try:
                logger.debug("[CredManager] Identifying credentials for periodic refresh...")
                
                candidates_to_refresh = []
                async with self.lock:
                    # 这里的锁至关重要，以防止在迭代过程中列表大小发生变化。
                    candidates_to_refresh = [c for c in self.credentials if self._should_proactively_refresh(c)]
                
                if candidates_to_refresh:
                    # 使用 id 去重，尽管逻辑上应该能防止重复，但这是一种安全措施。
                    unique_candidates_map = {c.id: c for c in candidates_to_refresh}
                    unique_candidates = list(unique_candidates_map.values())
                    if unique_candidates:
                        logger.info(f"[CredManager] Found {len(unique_candidates)} idle candidates for proactive refresh.")
                        for c in unique_candidates:
                            await self._refresh_credential(c)

                # 固定循环间隔
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                logger.info("[CredManager] Refresh loop cancelled.")
                break
            except Exception as e:
                logger.error(f"[CredManager] Refresh loop error: {e}", exc_info=True)
                await asyncio.sleep(60)

    async def _health_check_loop(self):
        """
        后台健康检查循环，主动发现“亚健康”凭据。
        """
        while True:
            try:
                # 1. 检查系统是否繁忙
                if self.system_tracker.active_requests_count > 0:
                    postpone_duration = HEALTH_CHECK_POSTPONE_INTERVAL_SEC * random.uniform(1.0, 1.5)
                    logger.debug(f"System is busy. Postponing health check for {postpone_duration:.2f} seconds.")
                    await asyncio.sleep(postpone_duration)
                    continue

                # 2. 动态计算带抖动的闲置阈值
                base_idle_sec = HEALTH_CHECK_IDLE_THRESHOLD_SEC
                random_idle_sec = base_idle_sec * random.uniform(0.5, 1.0)
                idle_threshold = timedelta(seconds=random_idle_sec)

                # 3. 在锁内快速识别出检查目标
                target_cred = None
                async with self.lock:
                    now = datetime.now(timezone.utc)
                    
                    candidates = [
                        c for c in self.credentials
                        if c.status in [CredentialStatus.ACTIVE, CredentialStatus.SUSPECTED] and 
                           c.credentials.refresh_token and
                           (not c.last_used_at or (now - c.last_used_at) > idle_threshold)
                    ]

                    if candidates:
                        # 总是选择最久未使用的凭据进行检查
                        # 为了处理 None，我们将 None 视为一个非常早的时间
                        target_cred = min(candidates, key=lambda c: c.last_used_at if c.last_used_at else datetime.min.replace(tzinfo=timezone.utc))

                # 4. 在锁外执行网络IO
                if target_cred:
                    logger.info(f"Performing health check on idle credential: {target_cred.log_safe_id} (idle for > {idle_threshold})")
                    check_result = await self.health_checker.check(target_cred)
                    is_healthy = check_result.get("is_healthy", False)
                    
                    # 在锁内更新状态
                    async with self.lock:
                        # 再次确认凭据状态没有在检查期间被改变
                        if target_cred.status in [CredentialStatus.ACTIVE, CredentialStatus.SUSPECTED]:
                            if not is_healthy:
                                target_cred.mark_suspected()
                            else:
                                # 无论之前是 ACTIVE 还是 SUSPECTED，只要检查通过，就标记为健康
                                # 如果检查通过，可以认为它“被使用”了一次，以更新其 last_used_at 时间戳
                                target_cred.mark_used()
                else:
                    # 没有需要检查的凭据，短暂休眠后继续
                    await asyncio.sleep(HEALTH_CHECK_POSTPONE_INTERVAL_SEC)
                    continue

                # 5. 随机化休眠以避免惊群效应
                await asyncio.sleep(HEALTH_CHECK_POSTPONE_INTERVAL_SEC * random.uniform(1.0, 1.5))

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

    async def force_health_check(self, credential_id: str) -> Dict[str, Any]:
        """
        对指定的凭据强制执行一次健康检查，并返回详细结果。
        """
        target_cred = None
        async with self.lock:
            for c in self.credentials:
                if c.id == credential_id:
                    target_cred = c
                    break
        
        if not target_cred:
            return {"error": "Credential not found", "credential_id": credential_id}

        previous_status = target_cred.status
        
        logger.info(f"Force running health check on credential: {target_cred.log_safe_id}")
        if self._should_proactively_refresh(target_cred):
            await self._refresh_credential(target_cred)
        check_result = await self.health_checker.check(target_cred)
        is_healthy = check_result.get("is_healthy", False)
        
        async with self.lock:
            if not is_healthy:
                target_cred.mark_suspected()
            else:
                target_cred.mark_healthy("Manual check passed")

            new_status = target_cred.status
            
            return {
                "credential_id": credential_id,
                "check_time": datetime.now(timezone.utc).isoformat(),
                "previous_status": previous_status,
                "new_status": new_status,
                "check_details": check_result
            }

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
