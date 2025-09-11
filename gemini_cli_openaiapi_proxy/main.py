"""
应用启动逻辑模块：
- 解析命令行参数。
- 加载配置。
- 初始化日志。
- 创建并运行 FastAPI 应用。
"""

import argparse
import logging.config
import sys
import uvicorn
import asyncio
from cryptography.fernet import Fernet

from .app import create_app
from .core.config import load_settings
from .core.logging_config import get_logging_config
from .cli.local_auth_handler import execute_local_oauth_flow

def run_server(args):
    """启动 FastAPI 服务器"""
    # 2. 加载配置
    settings = load_settings(args.config, args.encryption_key)

    # 3. 初始化日志
    log_level = settings.get("log_level", "info")
    logging_config = get_logging_config(log_level.upper())
    logging.config.dictConfig(logging_config)

    # 4. 创建 FastAPI 应用
    app = create_app(settings)

    # 5. 启动 uvicorn 服务器
    server_settings = settings["server"]
    uvicorn.run(
        app,
        host=server_settings["host"],
        port=server_settings["port"],
        log_config=logging_config,
    )

def generate_key(args):
    """生成一个新的 Fernet 加密密钥"""
    key = Fernet.generate_key()
    print("Generated new encryption key. Please store it securely:")
    print(key.decode())

def run_local_auth(args):
    """启动本地 OAuth2 流程来添加新凭据"""
    # 仅加载配置，不启动完整服务器
    settings = load_settings(args.config)
    try:
        asyncio.run(execute_local_oauth_flow(settings))
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

def run():
    """
    主运行函数，用于解析命令行参数并分发到相应的处理函数。
    """
    parser = argparse.ArgumentParser(
        description="Gemini API Proxy Server v2. Use 'run' to start the server or 'generate-key' to create a new encryption key."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'run' 子命令 (启动服务器)
    parser_run = subparsers.add_parser("run", help="Run the proxy server (default command)")
    parser_run.add_argument(
        "-c", "--config",
        type=str,
        help="Path to the configuration JSON file."
    )
    parser_run.add_argument(
        "-ek", "--encryption-key",
        type=str,
        help="Encryption key for the credentials file. Overrides environment variables."
    )
    parser_run.set_defaults(func=run_server)

    # 'generate-key' 子命令
    parser_gen_key = subparsers.add_parser("generate-key", help="Generate a new encryption key")
    parser_gen_key.set_defaults(func=generate_key)

    # 'auth' 子命令
    parser_auth = subparsers.add_parser("auth", help="Run local OAuth2 flow to add a new credential")
    parser_auth.add_argument(
        "-c", "--config",
        type=str,
        required=True, # 强制要求提供配置文件
        help="Path to the configuration JSON file."
    )
    parser_auth.set_defaults(func=run_local_auth)

    # 如果没有提供子命令，则默认为 'run'
    # 这使得 `python -m ...` 和 `python -m ... run` 效果相同
    args = parser.parse_args()
    if args.command is None:
        # 当没有子命令时，需要从 sys.argv 手动解析 'run' 命令的参数
        args = parser.parse_args(['run'] + sys.argv[1:])

    args.func(args)

if __name__ == "__main__":
    run()
