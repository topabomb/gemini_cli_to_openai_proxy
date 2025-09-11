"""
中间件模块。

定义了用于 FastAPI 应用的中间件，例如添加请求 ID 以便进行日志追踪。
"""

import time
import uuid
from contextvars import ContextVar
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send
from fastapi import Request
from ..services.state_tracker import SystemStateTracker

# 使用 ContextVar 来在整个请求处理链路中安全地传递请求 ID
# 明确类型为 Optional[str]，并提供 None 作为默认值
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    一个为每个进入的请求添加唯一 ID 的中间件。

    这个 ID 可用于日志记录，以便将分散在不同服务和函数中的日志条目
    关联到同一个请求，极大地简化了调试和问题追溯。
    """
    async def dispatch(
        self, request: Request, call_next
    ) -> Response:
        # 为请求生成一个唯一的 ID
        request_id = str(uuid.uuid4())
        
        # 将 ID 存储在 ContextVar 中，以便在应用的任何地方访问
        request_id_var.set(request_id)
        
        # 在响应头中也包含这个 ID，方便客户端进行关联
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        return response

class StateTrackingMiddleware(BaseHTTPMiddleware):
    """
    追踪系统中活动 API 请求数量的中间件。

    它通过在请求开始时递增计数器、在请求结束时递减计数器，
    来为 `SystemStateTracker` 服务提供实时数据。
    """
    def __init__(self, app: ASGIApp, tracker: SystemStateTracker):
        super().__init__(app)
        self.tracker = tracker

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        在请求处理前后更新活动请求计数。
        """
        self.tracker.increment()
        try:
            response = await call_next(request)
        finally:
            self.tracker.decrement()
        return response
