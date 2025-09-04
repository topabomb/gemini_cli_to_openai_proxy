"""
运行期全局状态容器：避免循环导入。
"""
# 由 app.py 在 startup 前注入
settings = None
credential_manager = None
api_client = None


