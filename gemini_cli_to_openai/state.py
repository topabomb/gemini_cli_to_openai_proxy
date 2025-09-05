"""
运行期全局状态容器模块：用于避免循环导入。

在复杂的应用中，模块之间可能会出现循环依赖，例如：
- `app.py` 需要导入 `routes` 模块来注册路由
- `routes` 模块需要导入 `app.py` 中定义的某些对象（如配置、客户端等）来处理请求

为了解决这个问题，我们创建一个独立的 `state.py` 模块来存放这些需要被多个模块共享的全局对象。
`app.py` 在启动时负责创建这些对象并将其赋值给 `state.py` 中的变量。
其他模块（如 `routes`, `client` 等）只需要导入 `state.py` 即可访问这些对象，而无需直接导入 `app.py`，从而打破了循环依赖。

此模块应在应用启动的早期阶段由 `app.py` 初始化所有变量，之后其他模块才能安全地使用它们。
"""

from typing import Any, Dict, Optional

from .credentials import CredentialManager
from .client import ApiClient
from .usage import UsageTracker

# 由 app.py 在 startup 前注入的全局状态变量
# 应用的配置字典
settings: Dict[str, Any] = {}
# 凭据管理器实例
credential_manager: Optional[CredentialManager] = None
# API 客户端实例
api_client: Optional[ApiClient] = None
# 用量跟踪器实例
usage_tracker: Optional[UsageTracker] = None
