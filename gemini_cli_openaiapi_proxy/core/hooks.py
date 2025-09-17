"""
Hook 系统核心模块：
- 提供请求生命周期的 Hook 机制
- 支持多个 Hook 串行执行
- 提供异常隔离和超时保护
- 替代原有的 UsageTracker 功能
"""

import json
import asyncio
import logging
import uuid
from typing import List, Optional, Callable, Awaitable, Any, Dict
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

class RequestDeniedError(Exception):
    """请求被拒绝的异常，用于在 Hook 中阻止请求继续执行"""
    def __init__(self, message: str, status_code: int = 403):
        super().__init__(message)
        self.status_code = status_code
        self.message = message

@dataclass
class AttemptInfo:
    """单次请求尝试的信息"""
    cred_id: str
    email_masked: str
    status_code: Optional[int] = None
    reason: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class RequestContext:
    """请求上下文，包含请求的完整生命周期信息"""
    request_id: str
    route: str  # "openai.chat" 或 "gemini.native"
    auth_key: str
    model: str
    is_streaming: bool
    compat_openai: bool
    
    # 凭据信息
    current_credential_id: Optional[str] = None
    current_credential_email: Optional[str] = None
    
    # 请求尝试记录
    attempts: List[AttemptInfo] = field(default_factory=list)
    
    # 用量元数据
    usage_metadata: Dict[str, Any] = field(default_factory=dict)
    
    # 时间戳
    start_time: datetime = field(default_factory=datetime.utcnow)
    first_byte_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # 结果状态
    success: Optional[bool] = None
    error: Optional[str] = None
    http_status: Optional[int] = None
    
    # 内部状态
    _end_triggered: bool = field(default=False, init=False)

    def add_attempt(self, cred_id: str, email_masked: str, status_code: Optional[int] = None, reason: Optional[str] = None):
        """添加一次请求尝试记录"""
        self.attempts.append(AttemptInfo(
            cred_id=cred_id,
            email_masked=email_masked,
            status_code=status_code,
            reason=reason
        ))

    def mark_success(self, http_status: int = 200, usage_metadata: Optional[Dict[str, Any]] = None):
        """标记请求成功"""
        self.success = True
        self.http_status = http_status
        if usage_metadata:
            self.usage_metadata.update(usage_metadata)

    def mark_failure(self, error: str, http_status: int = 500):
        """标记请求失败"""
        self.success = False
        self.error = error
        self.http_status = http_status

    def mark_first_byte(self):
        """标记首字节时间（用于流式请求）"""
        if self.first_byte_time is None:
            self.first_byte_time = datetime.utcnow()
    
    def update_credential(self, credential_id: str, credential_email: str):
        """更新当前使用的凭据信息"""
        self.current_credential_id = credential_id
        self.current_credential_email = credential_email

# Hook 函数类型定义
StartHook = Callable[[RequestContext], Awaitable[None]]
EndHook = Callable[[RequestContext], Awaitable[None]]

class HookManager:
    """Hook 管理器，负责注册和执行 Hook"""
    
    def __init__(self, start_timeout_ms: int = 200, end_timeout_ms: int = 400):
        self._start_hooks: List[StartHook] = []
        self._end_hooks: List[EndHook] = []
        self._start_timeout = start_timeout_ms / 1000
        self._end_timeout = end_timeout_ms / 1000

    def add_start_hook(self, hook: StartHook):
        """添加请求开始 Hook"""
        self._start_hooks.append(hook)
        logger.debug(f"Added start hook: {hook.__name__ if hasattr(hook, '__name__') else str(hook)}")

    def add_end_hook(self, hook: EndHook):
        """添加请求结束 Hook"""
        self._end_hooks.append(hook)
        logger.debug(f"Added end hook: {hook.__name__ if hasattr(hook, '__name__') else str(hook)}")

    async def trigger_start(self, ctx: RequestContext):
        """触发所有请求开始 Hook"""
        for i, hook in enumerate(self._start_hooks):
            try:
                await asyncio.wait_for(hook(ctx), timeout=self._start_timeout)
            except asyncio.TimeoutError:
                hook_name = getattr(hook, '__name__', f'hook_{i}')
                logger.warning(f"Start hook timeout: {hook_name}")
            except RequestDeniedError:
                # 请求拒绝异常需要向上传递
                raise
            except Exception as e:
                hook_name = getattr(hook, '__name__', f'hook_{i}')
                logger.error(f"Start hook error in {hook_name}: {e}", exc_info=True)

    async def trigger_end(self, ctx: RequestContext):
        """触发所有请求结束 Hook"""
        # 防止重复触发
        if ctx._end_triggered:
            return
        ctx._end_triggered = True
        
        # 设置结束时间
        if ctx.end_time is None:
            ctx.end_time = datetime.utcnow()
            
        for i, hook in enumerate(self._end_hooks):
            try:
                await asyncio.wait_for(hook(ctx), timeout=self._end_timeout)
            except asyncio.TimeoutError:
                hook_name = getattr(hook, '__name__', f'hook_{i}')
                logger.warning(f"End hook timeout: {hook_name}")
            except Exception as e:
                hook_name = getattr(hook, '__name__', f'hook_{i}')
                logger.error(f"End hook error in {hook_name}: {e}", exc_info=True)

def create_request_context(route: str, auth_key: str, model: str, is_streaming: bool, compat_openai: bool) -> RequestContext:
    """创建请求上下文的便捷函数"""
    return RequestContext(
        request_id=f"req-{uuid.uuid4()}",
        route=route,
        auth_key=auth_key,
        model=model,
        is_streaming=is_streaming,
        compat_openai=compat_openai
    )