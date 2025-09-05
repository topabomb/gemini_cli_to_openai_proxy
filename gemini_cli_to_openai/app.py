"""
应用装配模块：
- 创建 FastAPI 实例，注册路由。
- startup：导入外部凭据、加载池、确保最小凭据数、启动刷新任务和用量统计任务。
- shutdown：停止后台任务。
"""

import logging
from typing import cast
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from .credentials import CredentialManager
from .client import ApiClient
from .auth import run_oauth_flow, onboard_user
from .config import SettingsDict


def create_app(settings: SettingsDict) -> FastAPI:
    app = FastAPI()

    # 允许 CORS 预检
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 状态注入（避免循环导入）
    from . import state as _state
    from .usage import UsageTracker

    _state.settings = settings
    _state.credential_manager = CredentialManager(settings)
    _state.api_client = ApiClient(_state.credential_manager, settings)
    _state.usage_tracker = UsageTracker(_state.credential_manager)

    from .routes_openai import router as openai_router
    from .routes_gemini import router as gemini_router

    @app.on_event("startup")
    async def _startup():
        from .config import SUPPORTED_MODELS

        try:
            logging.info("Starting Gemini proxy server...")

            # 打印已配置的基础模型
            base_models = sorted(list(set([m["name"].replace("models/", "") for m in SUPPORTED_MODELS])))
            logging.info(f"Proxy configured with base models: {base_models}")
            logging.info("To add new models, please update SUPPORTED_MODELS in gemini_cli_to_openai/config.py")

            # 导入外部凭据（按配置）
            _state.credential_manager.import_external()
            # 加载持久化凭据
            _state.credential_manager.load()
            # 确保最小凭据数，不足则提示用户执行 OAuth（此处仅日志提醒，流程可在管理端触发）
            min_required = settings["min_credentials"]
            active = _state.credential_manager.get_active_credential_count()
            if active < min_required:
                logging.warning(
                    "Active credentials fewer than min_credentials. Starting interactive OAuth flow..."
                )
                _interactive_oauth_acquire(settings, _state)
            # 启动后台刷新
            _state.credential_manager.start_refresh_task()
            # 启动用量统计日志
            if settings["usage_logging"]["enabled"]:
                interval = settings["usage_logging"]["interval_sec"]
                _state.usage_tracker.start_logging_task(interval)

            logging.info(
                f"Loaded { _state.credential_manager.get_credential_count() } credentials, { _state.credential_manager.get_active_credential_count() } active"
            )
        except Exception as e:
            logging.error(f"Startup error: {e}")

    @app.on_event("shutdown")
    def _shutdown():
        logging.info("Shutting down server...")
        _state.credential_manager.stop_refresh_task()
        if _state.usage_tracker:
            _state.usage_tracker.stop_logging_task()

    # 根与健康检查
    @app.options("/{full_path:path}")
    async def handle_preflight(request: Request, full_path: str):
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    @app.get("/")
    async def root():
        return {
            "name": "gemini_cli_to_openai",
            "description": "OpenAI-compatible API proxy for Google's Gemini models via gemini-cli",
            "endpoints": {
                "openai": {
                    "chat_completions": "/v1/chat/completions",
                    "models": "/v1/models",
                },
                "gemini": {"models": "/v1beta/models", "proxy": "/{...}"},
                "health": "/health",
            },
        }

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "gemini_cli_to_openai"}

    app.include_router(openai_router)
    app.include_router(gemini_router)
    return app


def _interactive_oauth_acquire(settings: SettingsDict, _state):
    """交互式 OAuth 获取凭据，直到满足 min_credentials。"""
    target = settings["min_credentials"]
    attempts = 0
    max_attempts = max(3, target * 3)
    while (
        _state.credential_manager.get_active_credential_count() < target
        and attempts < max_attempts
    ):
        attempts += 1
        logging.info(
            f"OAuth attempt {attempts}/{max_attempts} - active={_state.credential_manager.get_active_credential_count()} target={target}"
        )
        creds = run_oauth_flow()
        if not creds:
            logging.error(
                "OAuth flow returned no credentials. Prompting user to retry..."
            )
            continue
        # 记录关键信息
        has_rt = bool(getattr(creds, "refresh_token", None))
        has_token = bool(getattr(creds, "token", None))
        logging.info(
            f"OAuth received credentials: has_refresh_token={has_rt}, has_access_token={has_token}"
        )
        # 尝试添加至池并持久化
        ok, reason = _state.credential_manager.add_credentials(creds)
        if not ok:
            logging.error(
                f"Add credential failed: {reason}. Please try a different account or re-consent."
            )
            continue
        # Onboard（容错处理）
        try:
            # 找到刚刚添加的最后一条
            mc = _state.credential_manager.credentials[-1]
            logging.info(f"Onboarding user: email={mc.email}, project={mc.project_id}")
            onboard_user(mc.credentials, mc.project_id)
            logging.info("Onboarding completed.")
        except Exception as e:
            logging.warning(f"Onboarding failed (non-blocking): {e}")
    if _state.credential_manager.get_active_credential_count() < target:
        logging.error(
            "OAuth acquisition did not reach min_credentials. Service will run with limited capability."
        )
