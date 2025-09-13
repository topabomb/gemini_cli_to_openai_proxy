"""
应用装配模块：
- 创建并配置 FastAPI 实例。
- 注册生命周期事件和 API 路由。
"""

from fastapi import FastAPI
from .core.config import SettingsDict
from .core.lifespan import lifespan
from .core.middleware import RequestIdMiddleware, StateTrackingMiddleware
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

    # 添加状态追踪中间件
    # 注意：它必须在 lifespan 上下文之后被添加，以便能访问 app.state.system_tracker
    @app.on_event("startup")
    async def add_state_tracking_middleware():
        app.add_middleware(StateTrackingMiddleware, tracker=app.state.system_tracker)

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
    from fastapi import APIRouter

    # 创建一个用于公开端点的路由器
    public_router = APIRouter()

    @public_router.get("/health", tags=["Public"])
    async def health_check():
        """公开的健康检查端点。"""
        return {"status": "healthy"}

    app.include_router(public_router)
    app.include_router(admin.router)
    app.include_router(gemini.router)
    app.include_router(openai.router)

    # 注册全局异常处理器
    app.add_exception_handler(Exception, generic_exception_handler)

    return app
