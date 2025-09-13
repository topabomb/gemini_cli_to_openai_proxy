"""
核心类型定义模块。

该文件包含了应用内部跨模块共享的、非 API 模型的类型定义、
数据类和类型别名，以促进代码的类型安全和解耦。
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import random
from typing import Optional, Callable, Awaitable, Tuple

from google.oauth2.credentials import Credentials
from ..utils.sanitizer import sanitize_email

logger = logging.getLogger(__name__)

# ===== 类型别名 =====

# 代表一个原子健康检查函数，返回一个包含健康状态和描述信息的元组
AtomicHealthCheck = Callable[['ManagedCredential'], Awaitable[Tuple[bool, str]]]


# ===== 数据类 =====

class CredentialStatus:
    """定义了凭据可能处于的所有状态。"""
    ACTIVE = "active"
    EXPIRED = "expired"
    SUSPECTED = "suspected"  # Health check failed, but still usable
    REFRESHING = "refreshing"
    RATE_LIMITED = "rate_limited"  # 429
    PERMISSION_DENIED = "permission_denied"  # 403
    ERROR = "error"  # Unrecoverable

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
    rate_limited_until: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    
    # 统计与状态
    usage_count: int = 0
    failure_reason: Optional[str] = None

    @property
    def log_safe_id(self) -> str:
        """返回一个对日志安全的凭据标识符。"""
        return f"{self.id}({sanitize_email(self.email)})"
    def should_proactively_refresh(self, ) -> bool:
        """判断一个凭据是否应该由后台循环进行主动刷新。"""
        now = datetime.now(timezone.utc)

        if not self.credentials.refresh_token:
            return False

        # 1. 安全锁：不要触碰最近活跃过的凭据。
        if self.last_used_at and (now - self.last_used_at) < timedelta(minutes=30) and self.status != CredentialStatus.EXPIRED:
            return False

        # 2. 恢复性刷新：用于从速率限制中恢复的凭据。
        is_rate_limited_and_recovered = (
            self.status == CredentialStatus.RATE_LIMITED and
            self.rate_limited_until and now > self.rate_limited_until
        )
        if is_rate_limited_and_recovered:
            return True

        # 3. 预防性/修复性刷新：用于即将过期或已过期的凭据。
        is_in_expiry_check_scope = self.status in [
            CredentialStatus.ACTIVE,
            CredentialStatus.SUSPECTED,
            CredentialStatus.EXPIRED
        ]
        if is_in_expiry_check_scope and self.credentials.expiry:
            # 确保expiry有时区信息
            expiry_time = self.credentials.expiry
            if expiry_time.tzinfo is None:
                expiry_time = expiry_time.replace(tzinfo=timezone.utc)
            random_expiry_window = timedelta(minutes=random.randint(1, 10))
            # 如果凭据将在随机窗口内过期（这也包含了已经过期的情况），则刷新。
            return expiry_time < now + random_expiry_window
        
        return False

    def is_available(self) -> bool:
        """检查凭据当前是否可用，并在此过程中更新瞬时状态（如过期）。"""
        # 如果一个凭据的冷静期结束，将其状态恢复为 ACTIVE
        if self.status == CredentialStatus.RATE_LIMITED:
            if self.rate_limited_until and datetime.now(timezone.utc) > self.rate_limited_until:
                self.mark_healthy("Recovered from rate limit")
        
        # SUSPECTED 状态的凭据被认为是可用的，以促进自愈
        if self.status not in [CredentialStatus.ACTIVE, CredentialStatus.SUSPECTED]:
            return False
        
        # 检查凭据是否已过期
        is_expired = False
        if self.credentials.expiry:
            expiry_utc = self.credentials.expiry if self.credentials.expiry.tzinfo is not None else self.credentials.expiry.replace(tzinfo=timezone.utc)
            is_expired = expiry_utc < datetime.now(timezone.utc)

        if is_expired:
            self.status = CredentialStatus.EXPIRED
            return False
            
        return True

    def mark_used(self):
        """标记凭据被使用，并处理 SUSPECTED 状态的自愈。"""
        self.last_used_at = datetime.now(timezone.utc)
        self.usage_count += 1
        
        # 如果一个“可疑”凭据被成功使用，它就证明了自己是健康的
        if self.status == CredentialStatus.SUSPECTED:
            self.mark_healthy("Self-healed after successful use")

    def mark_expired(self):
        """主动将凭据标记为过期状态，通常在收到 401 后调用。"""
        if self.status != CredentialStatus.EXPIRED:
            self.status = CredentialStatus.EXPIRED
            self.failure_reason = "401 Unauthorized (token expired)"
            self.failed_at = datetime.now(timezone.utc)
            logger.warning(f"Credential {self.log_safe_id} marked as EXPIRED due to 401 error.")

    def mark_healthy(self, reason: str):
        """将凭据标记为健康状态。"""
        if self.status != CredentialStatus.ACTIVE:
            logger.info(f"Credential {self.log_safe_id} is now ACTIVE. Reason: {reason}")
            self.status = CredentialStatus.ACTIVE
            self.failure_reason = None
            self.failed_at = None
            self.rate_limited_until = None

    def mark_suspected(self):
        """将凭据标记为“可疑”状态，通常在健康检查失败后调用。"""
        if self.status != CredentialStatus.SUSPECTED:
            self.status = CredentialStatus.SUSPECTED
            self.failure_reason = "Health check failed"
            self.failed_at = datetime.now(timezone.utc)
            logger.warning(f"Credential {self.log_safe_id} marked as SUSPECTED due to health check failure.")

    def mark_rate_limited(self, minutes: int = 30):
        self.status = CredentialStatus.RATE_LIMITED
        self.rate_limited_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        self.failure_reason = "429 Too Many Requests"
        self.failed_at = datetime.now(timezone.utc)

    def mark_permission_denied(self):
        self.status = CredentialStatus.PERMISSION_DENIED
        self.failure_reason = "403 Forbidden"
        self.failed_at = datetime.now(timezone.utc)

    def mark_as_permanent_error(self, reason: str):
        self.status = CredentialStatus.ERROR
        self.failure_reason = reason
        self.failed_at = datetime.now(timezone.utc)
