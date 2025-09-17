"""
API 依赖注入模块。

提供用于 FastAPI 路由的依赖项，以便从应用状态中获取服务实例。
"""

from fastapi import Request
from ..services.google_client import GoogleApiClient
from ..services.credential_manager import CredentialManager
from ..core.hooks import HookManager
from ..services.usage_hooks import UsageStatsHook

def get_google_api_client(request: Request) -> GoogleApiClient:
    """依赖项：从应用状态获取 GoogleApiClient 实例。"""
    return request.app.state.google_api_client

def get_credential_manager(request: Request) -> CredentialManager:
    """依赖项：从应用状态获取 CredentialManager 实例。"""
    return request.app.state.credential_manager

def get_hook_manager(request: Request) -> HookManager:
    """依赖项：从应用状态获取 HookManager 实例。"""
    return request.app.state.hook_manager

def get_usage_stats_hook(request: Request) -> UsageStatsHook:
    """依赖项：从应用状态获取 UsageStatsHook 实例。"""
    return request.app.state.usage_stats_hook
