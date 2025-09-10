"""
应用装配模块：
- 创建并配置 FastAPI 实例。
- 注册生命周期事件和 API 路由。
"""

from fastapi import FastAPI
from .core.config import SettingsDict
from .core.lifespan import lifespan
from .core.middleware import RequestIdMiddleware
from .api.routes import admin, gemini
from .api.exception_handlers import generic_exception_handler

def create_app(settings: SettingsDict) -> FastAPI:
    """
    创建并返回一个配置好的 FastAPI 应用实例。
    """
    app = FastAPI(
        title="Gemini API Proxy",
        description="A high-performance proxy for Google's Gemini models, compatible with the OpenAI API.",
        version="2.0.0",
        lifespan=lifespan,
    )

    # 将配置存储在应用状态中，以便在各处访问
    app.state.settings = settings

    # 添加请求 ID 中间件
    app.add_middleware(RequestIdMiddleware)

    # 允许所有来源的 CORS
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 注册 API 路由
    from .api.routes import openai
    app.include_router(admin.router)
    app.include_router(gemini.router)
    app.include_router(openai.router)

    # 注册全局异常处理器
    app.add_exception_handler(Exception, generic_exception_handler)

    return app
