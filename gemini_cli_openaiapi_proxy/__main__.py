"""
模块化运行入口点：
- 允许通过 `python -m gemini_cli_openaiapi_proxy` 命令启动应用。
"""

from .main import run

if __name__ == "__main__":
    run()
