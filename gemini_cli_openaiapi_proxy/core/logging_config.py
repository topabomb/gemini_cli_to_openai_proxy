"""
日志配置模块：
- 使用 dictConfig 提供结构化的日志配置。
- 统一应用日志和 uvicorn 访问日志的格式。
- 注入 request_id 以便追踪。
"""

import logging
from typing import Dict, Any

from ..core.middleware import request_id_var

class RequestIdFilter(logging.Filter):
    """一个将请求 ID 注入日志记录的过滤器。"""
    def filter(self, record):
        record.request_id = request_id_var.get()
        return True

def get_logging_config(log_level: str) -> Dict[str, Any]:
    """
    生成日志配置字典。
    """
    LOG_LEVEL = log_level.upper()
    
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "request_id_filter": {
                "()": RequestIdFilter,
            },
        },
        "formatters": {
            "default": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "access": {
                "format": "%(asctime)s - [%(request_id)s] - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "filters": ["request_id_filter"],
                "stream": "ext://sys.stdout",
            },
            "access": {
                "class": "logging.StreamHandler",
                "formatter": "access",
                "filters": ["request_id_filter"],
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "gemini_cli_openaiapi_proxy": {
                "handlers": ["default"],
                "level": LOG_LEVEL,
                "propagate": False,
            },
            # 移除 uvicorn 根 logger 的 handler，避免重复
            "uvicorn": {
                "handlers": [],
                "level": LOG_LEVEL,
                "propagate": False,
            },
            "uvicorn.error": {
                "handlers": ["default"],
                "level": LOG_LEVEL,
                "propagate": False,
            },
            "uvicorn.access": {
                "handlers": ["access"],
                "level": LOG_LEVEL,
                "propagate": False,
            },
        },
    }
