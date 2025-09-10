"""
全局异常处理模块：
- 定义并注册用于捕获未处理异常的处理器。
- 提供丰富的错误日志上下文。
"""

import logging
from fastapi import Request
from fastapi.responses import JSONResponse

async def generic_exception_handler(request: Request, exc: Exception):
    """
    捕获所有未处理的异常，记录详细信息，并返回一个标准的 500 错误。
    """
    logging.error(
        f"Unhandled exception for request: {request.method} {request.url}",
        exc_info=True,  # 包含完整的 traceback
        extra={
            "client": request.client,
            "headers": dict(request.headers),
        }
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "An internal server error occurred.",
                "type": "internal_error",
            }
        },
    )
