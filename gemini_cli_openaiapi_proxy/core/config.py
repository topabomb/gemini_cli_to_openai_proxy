"""
配置模块：
- 定义了应用的所有配置项 (SettingsDict)。
- 提供 load_settings 函数，用于从 JSON 文件加载配置并与默认值合并。
- 包含 Google OAuth 和 API 的硬编码常量。
"""

import base64
import json
import os
from typing import Any, Dict, List, Optional, TypedDict, Union

# ===== 硬编码 OAuth 配置 =====
# 这些是项目预设的客户端凭据，保持不变
_ENCODED_CLIENT_ID = "NjgxMjU1ODA5Mzk1LW9vOGZ0Mm9wcmRybnA5ZTNhcWY2YXYzaG1kaWIxMzVqLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t"
_ENCODED_CLIENT_SECRET = "R09DU1BYLTR1SGdNUG0tMW83U2stZ2VWNkN1NWNsWEZzeGw="

CLIENT_ID = base64.b64decode(_ENCODED_CLIENT_ID).decode("utf-8")
CLIENT_SECRET = base64.b64decode(_ENCODED_CLIENT_SECRET).decode("utf-8")
SCOPES: List[str] = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

# ===== Google API 端点与默认安全设置 =====
CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com"

DEFAULT_SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_IMAGE_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_IMAGE_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_IMAGE_HATE", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_IMAGE_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_UNSPECIFIED", "threshold": "BLOCK_NONE"},
]



# ===== 类型定义 =====
class ServerSettings(TypedDict):
    host: str
    port: int

class TimeoutsSettings(TypedDict):
    connect: int
    read: int

class UsageLoggingSettings(TypedDict):
    enabled: bool
    interval_sec: int

class SettingsDict(TypedDict):
    server: ServerSettings
    auth_keys: List[str]
    credentials_file: str
    project_id_map: Dict[str, str]
    log_level: str
    request_timeouts: TimeoutsSettings
    usage_logging: UsageLoggingSettings
    public_url: Optional[str]
    min_credentials: int

# ===== 默认配置 =====
def _get_default_settings() -> SettingsDict:
    """生成默认配置。"""
    # 将凭据文件路径设置为相对于当前工作目录
    credentials_path = os.path.join(os.getcwd(), "credentials1.json")
    
    data: SettingsDict = {
        "server": {"host": "0.0.0.0", "port": 8889},
        "auth_keys": ["123456"],
        "credentials_file": credentials_path,
        "project_id_map": {},
        "log_level": "debug",
        "request_timeouts": {"connect": 60, "read": 90},
        "usage_logging": {"enabled": True, "interval_sec": 30},
        "public_url": None,
        "min_credentials": 1,
    }
    return data

def load_settings(config_path: Optional[str] = None) -> SettingsDict:
    """从指定路径读取配置文件，与默认值合并。"""
    settings = _get_default_settings()

    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            user_config = json.load(f)

        # 合并配置
        server_config = user_config.get("server", {})
        settings["server"]["host"] = server_config.get("host", settings["server"]["host"])
        settings["server"]["port"] = int(server_config.get("port", settings["server"]["port"]))

        if "auth_keys" in user_config:
            keys = user_config["auth_keys"]
            settings["auth_keys"] = [keys] if isinstance(keys, str) else keys

        if "credentials_file" in user_config:
            # 将用户提供的相对路径转换为绝对路径
            settings["credentials_file"] = os.path.abspath(user_config["credentials_file"])

        if "project_id_map" in user_config:
            settings["project_id_map"] = user_config["project_id_map"]
        
        if "log_level" in user_config:
            settings["log_level"] = user_config["log_level"]

        timeouts_config = user_config.get("request_timeouts", {})
        settings["request_timeouts"]["connect"] = timeouts_config.get("connect", settings["request_timeouts"]["connect"])
        settings["request_timeouts"]["read"] = timeouts_config.get("read", settings["request_timeouts"]["read"])

        usage_config = user_config.get("usage_logging", {})
        settings["usage_logging"]["enabled"] = usage_config.get("enabled", settings["usage_logging"]["enabled"])
        settings["usage_logging"]["interval_sec"] = usage_config.get("interval_sec", settings["usage_logging"]["interval_sec"])

        if "public_url" in user_config:
            settings["public_url"] = user_config["public_url"]
        
        if "min_credentials" in user_config:
            settings["min_credentials"] = int(user_config["min_credentials"])

    return settings
