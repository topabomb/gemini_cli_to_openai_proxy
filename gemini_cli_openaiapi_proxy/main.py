"""
应用启动逻辑模块：
- 解析命令行参数。
- 加载配置。
- 初始化日志。
- 创建并运行 FastAPI 应用。
"""

import argparse
import logging.config
import uvicorn
from .app import create_app
from .core.config import load_settings
from .core.logging_config import get_logging_config

def run():
    """
    主运行函数，用于启动整个应用。
    """
    # 1. 处理命令行参数
    parser = argparse.ArgumentParser(description="Gemini API Proxy Server v2")
    parser.add_argument(
        "-c", "--config",
        type=str,
        help="Path to the configuration JSON file."
    )
    args = parser.parse_args()

    # 2. 加载配置
    settings = load_settings(args.config)

    # 3. 初始化日志
    log_level = settings.get("log_level", "INFO")
    logging_config = get_logging_config(log_level)
    logging.config.dictConfig(logging_config)

    # 4. 创建 FastAPI 应用
    app = create_app(settings)

    # 5. 启动 uvicorn 服务器
    server_settings = settings["server"]
    uvicorn.run(
        app,
        host=server_settings["host"],
        port=server_settings["port"],
        log_config=logging_config, # 将日志配置传递给 uvicorn
    )

if __name__ == "__main__":
    run()
