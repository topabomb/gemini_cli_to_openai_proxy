"""
程序入口：读取当前工作目录下的 config.json，装配并启动服务。
"""
import json
import logging
import os
import uvicorn
from typing import cast
import argparse # 引入 argparse 模块


def main():
    # 1. 处理命令行参数
    parser = argparse.ArgumentParser(description="Gemini CLI to API Proxy server.")
    parser.add_argument(
        "-c", "--config",
        type=str,
        help="Path to the configuration JSON file (default: config.json in current directory)."
    )
    args = parser.parse_args()

    # 2. 加载配置
    config_path = args.config
    if config_path is not None and not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    # 延迟导入，避免模块级副作用
    from .config import load_settings,default_settings
    if config_path is None:
        settings = default_settings
    else:
        settings = load_settings(config_path)

    # 初始化日志
    log_level = getattr(logging, settings.get("log_level", "INFO").upper(), logging.INFO)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # 构建应用
    from .app import create_app
    app = create_app(settings)

    # 启动 uvicorn
    server = settings.get("server", {})
    host = server.get("host", "0.0.0.0")
    port = int(server.get("port", 8888))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
