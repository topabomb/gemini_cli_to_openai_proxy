"""
应用生命周期管理模块：
- 使用 FastAPI 的 lifespan 上下文管理器。
- 在应用启动时初始化并注入服务实例。
- 在应用关闭时优雅地释放资源。
"""

import logging
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI

from ..services.credential_manager import CredentialManager
from ..services.google_client import GoogleApiClient
from ..services.usage_tracker import UsageTracker

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    应用生命周期管理器。
    """
    # ===== 应用启动 =====
    logging.info("Application startup...")
    settings = app.state.settings
    
    # 1. 创建共享的 httpx.AsyncClient
    http_client = httpx.AsyncClient()
    app.state.http_client = http_client
    
    # 2. 初始化核心服务
    cred_manager = CredentialManager(settings, http_client)
    app.state.credential_manager = cred_manager
    
    usage_tracker = UsageTracker(cred_manager)
    app.state.usage_tracker = usage_tracker
    
    # 注意：google_api_client 依赖其他服务，所以最后初始化
    google_api_client = GoogleApiClient(settings, cred_manager, http_client, usage_tracker)
    app.state.google_api_client = google_api_client
    
    # 3. 加载持久化凭据并检查
    await cred_manager.load_credentials()
    
    # 启动时凭据数量检查
    min_creds_required = settings.get("min_credentials", 1)
    if min_creds_required > 0:
        all_creds = cred_manager.get_all_credential_details()
        available_creds_count = sum(1 for c in all_creds if c.get("is_available"))
        
        if available_creds_count < min_creds_required:
            public_url = settings.get("public_url")
            if public_url:
                # 确保基础 URL 没有尾部斜杠，然后添加直达路径
                base_url = public_url.rstrip('/')
                admin_url = f"{base_url}/oauth2/login"
            else:
                host = settings["server"]["host"]
                port = settings["server"]["port"]
                # 将 0.0.0.0 替换为 localhost 以便本地访问
                display_host = "localhost" if host == "0.0.0.0" else host
                admin_url = f"http://{display_host}:{port}/oauth2/login"
            
            # 使用命名的 logger
            logger = logging.getLogger(__name__)
            logger.warning(
                f"Available credentials ({available_creds_count}) is less than "
                f"the required minimum ({min_creds_required}). "
                f"Please add more credentials via the admin page: {admin_url}"
            )

    # 4. 启动后台任务
    cred_manager.start_refresh_task()
    if settings["usage_logging"]["enabled"]:
        usage_tracker.start_logging_task(settings["usage_logging"]["interval_sec"])
        
    logging.info("Application startup complete.")
    
    yield
    
    # ===== 应用关闭 =====
    logging.info("Application shutdown...")
    
    # 1. 停止后台任务
    app.state.credential_manager.stop_refresh_task()
    if app.state.settings["usage_logging"]["enabled"]:
        app.state.usage_tracker.stop_logging_task()
        
    # 2. 关闭 httpx 客户端
    await app.state.http_client.aclose()
    
    logging.info("Application shutdown complete.")
