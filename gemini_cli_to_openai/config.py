"""
配置模块：
- 提供 `default_settings`（无入参时使用的默认配置）。
- 提供 `load_settings(config_path)`：从指定 JSON 文件加载并与默认值合并，路径归一化。
- 提供硬编码的 OAuth 客户端常量与模型常量。
- 仅使用配置/参数驱动，不读取环境变量。
"""

import base64
import json
import os
from typing import Any, Dict, List, Optional, TypedDict, Union, cast


# ===== 硬编码 OAuth 配置 =====
_ENCODED_CLIENT_ID = "NjgxMjU1ODA5Mzk1LW9vOGZ0Mm9wcmRybnA5ZTNhcWY2YXYzaG1kaWIxMzVqLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t"
_ENCODED_CLIENT_SECRET = "R09DU1BYLTR1SGdNUG0tMW83U2stZ2VWNkN1NWNsWEZzeGw="

CLIENT_ID = base64.b64decode(_ENCODED_CLIENT_ID).decode(
    "utf-8"
)  # Google OAuth 2.0 客户端 ID (Client ID)
CLIENT_SECRET = base64.b64decode(_ENCODED_CLIENT_SECRET).decode(
    "utf-8"
)  # Google OAuth 2.0 客户端密钥 (Client Secret)
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


# ===== 模型常量与帮助函数 =====
BASE_MODELS = [
    {
        "name": "models/gemini-2.5-pro-preview-05-06",
        "version": "001",
        "displayName": "Gemini 2.5 Pro Preview 05-06",
        "description": "Preview version of Gemini 2.5 Pro from May 6th",
        "inputTokenLimit": 1048576,
        "outputTokenLimit": 65535,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        "temperature": 1.0,
        "maxTemperature": 2.0,
        "topP": 0.95,
        "topK": 64,
    },
    {
        "name": "models/gemini-2.5-pro-preview-06-05",
        "version": "001",
        "displayName": "Gemini 2.5 Pro Preview 06-05",
        "description": "Preview version of Gemini 2.5 Pro from June 5th",
        "inputTokenLimit": 1048576,
        "outputTokenLimit": 65535,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        "temperature": 1.0,
        "maxTemperature": 2.0,
        "topP": 0.95,
        "topK": 64,
    },
    {
        "name": "models/gemini-2.5-pro",
        "version": "001",
        "displayName": "Gemini 2.5 Pro",
        "description": "Advanced multimodal model with enhanced capabilities",
        "inputTokenLimit": 1048576,
        "outputTokenLimit": 65535,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        "temperature": 1.0,
        "maxTemperature": 2.0,
        "topP": 0.95,
        "topK": 64,
    },
    {
        "name": "models/gemini-2.5-flash-preview-05-20",
        "version": "001",
        "displayName": "Gemini 2.5 Flash Preview 05-20",
        "description": "Preview version of Gemini 2.5 Flash from May 20th",
        "inputTokenLimit": 1048576,
        "outputTokenLimit": 65535,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        "temperature": 1.0,
        "maxTemperature": 2.0,
        "topP": 0.95,
        "topK": 64,
    },
    {
        "name": "models/gemini-2.5-flash-preview-04-17",
        "version": "001",
        "displayName": "Gemini 2.5 Flash Preview 04-17",
        "description": "Preview version of Gemini 2.5 Flash from April 17th",
        "inputTokenLimit": 1048576,
        "outputTokenLimit": 65535,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        "temperature": 1.0,
        "maxTemperature": 2.0,
        "topP": 0.95,
        "topK": 64,
    },
    {
        "name": "models/gemini-2.5-flash",
        "version": "001",
        "displayName": "Gemini 2.5 Flash",
        "description": "Fast and efficient multimodal model with latest improvements",
        "inputTokenLimit": 1048576,
        "outputTokenLimit": 65535,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        "temperature": 1.0,
        "maxTemperature": 2.0,
        "topP": 0.95,
        "topK": 64,
    },
]


def _generate_search_variants():
    """根据基础模型生成 -search 变体。"""
    search_models = []
    for model in BASE_MODELS:
        if "generateContent" in model["supportedGenerationMethods"]:
            search_variant = model.copy()
            search_variant["name"] = model["name"] + "-search"
            search_variant["displayName"] = model["displayName"] + " with Google Search"
            search_variant["description"] = (
                model["description"] + " (includes Google Search grounding)"
            )
            search_models.append(search_variant)
    return search_models


def _generate_thinking_variants():
    """根据基础模型生成 -nothinking 与 -maxthinking 变体。"""
    thinking_models = []
    for model in BASE_MODELS:
        if "generateContent" in model["supportedGenerationMethods"] and (
            "gemini-2.5-flash" in model["name"] or "gemini-2.5-pro" in model["name"]
        ):
            nt = model.copy()
            nt["name"] = model["name"] + "-nothinking"
            nt["displayName"] = model["displayName"] + " (No Thinking)"
            nt["description"] = model["description"] + " (thinking disabled)"
            thinking_models.append(nt)

            mt = model.copy()
            mt["name"] = model["name"] + "-maxthinking"
            mt["displayName"] = model["displayName"] + " (Max Thinking)"
            mt["description"] = model["description"] + " (maximum thinking budget)"
            thinking_models.append(mt)
    return thinking_models


all_models = BASE_MODELS + _generate_search_variants() + _generate_thinking_variants()
SUPPORTED_MODELS = sorted(all_models, key=lambda x: x["name"])


def get_base_model_name(model_name: str) -> str:
    """去掉模型名的变体后缀。"""
    suffixes = ["-maxthinking", "-nothinking", "-search"]
    for s in suffixes:
        if model_name.endswith(s):
            return model_name[: -len(s)]
    return model_name


def is_search_model(model_name: str) -> bool:
    """是否 search 变体。"""
    return "-search" in model_name


def is_nothinking_model(model_name: str) -> bool:
    return "-nothinking" in model_name


def is_maxthinking_model(model_name: str) -> bool:
    return "-maxthinking" in model_name


def get_thinking_budget(model_name: str) -> int:
    base_model = get_base_model_name(model_name)
    if is_nothinking_model(model_name):
        if "gemini-2.5-flash" in base_model:
            return 0
        elif "gemini-2.5-pro" in base_model:
            return 128
    elif is_maxthinking_model(model_name):
        if "gemini-2.5-flash" in base_model:
            return 24576
        elif "gemini-2.5-pro" in base_model:
            return 32768
    else:
        return -1
    return -1


def should_include_thoughts(model_name: str) -> bool:
    if is_nothinking_model(model_name):
        base_model = get_base_model_name(model_name)
        return "gemini-2.5-pro" in base_model
    return True


def _abspath(path: Optional[str]) -> Optional[str]:
    """将相对路径转换为绝对路径（相对于当前工作目录）。"""
    if not path:
        return None
    return path if os.path.isabs(path) else os.path.join(os.getcwd(), path)


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
    auth_keys: Union[str, List[str]]
    credentials_file: str
    external_credentials_file: Optional[str]
    project_id_map: Dict[str, str]
    min_credentials: int
    log_level: str
    request_timeouts: TimeoutsSettings
    usage_logging: UsageLoggingSettings


# ===== 默认配置 =====
def _make_default_settings() -> SettingsDict:
    """生成默认配置（含路径归一化）。"""
    # Define as a literal with the correct types
    data: SettingsDict = {
        "server": {"host": "0.0.0.0", "port": 8888},
        "auth_keys": ["123456"],
        "credentials_file": "credentials.json",
        "external_credentials_file": None,
        "project_id_map": {},
        "min_credentials": 1,
        "log_level": "INFO",
        "request_timeouts": {"connect": 60, "read": 90},
        "usage_logging": {"enabled": True, "interval_sec": 30},
    }
    # Make paths absolute, ensuring no None is assigned to non-optional type
    abs_cred_file = _abspath(data["credentials_file"])
    if abs_cred_file is None:
        raise ValueError("Default credentials_file path is invalid and resulted in None.")
    data["credentials_file"] = abs_cred_file
    
    data["external_credentials_file"] = _abspath(data.get("external_credentials_file"))
    return data


default_settings: SettingsDict = _make_default_settings()


def _normalize_settings(data: Dict[str, Any]) -> SettingsDict:
    """与默认配置合并并做路径归一化与基本校验。"""
    settings = default_settings.copy()
    user_data = data or {}

    # Server settings
    server_in = user_data.get("server", {})
    if server_in:
        settings["server"]["host"] = server_in.get("host", default_settings["server"]["host"])
        settings["server"]["port"] = int(server_in.get("port", default_settings["server"]["port"]))

    # Auth keys
    auth_keys = user_data.get("auth_keys")
    if auth_keys:
        if isinstance(auth_keys, str):
            settings["auth_keys"] = [auth_keys]
        else:
            settings["auth_keys"] = auth_keys
    
    # File paths
    cred_file = user_data.get("credentials_file")
    if cred_file:
        abs_path = _abspath(cred_file)
        if abs_path:
            settings["credentials_file"] = abs_path

    ext_cred_file = user_data.get("external_credentials_file")
    if ext_cred_file:
        settings["external_credentials_file"] = _abspath(ext_cred_file)
    elif "external_credentials_file" in user_data: # handle explicit null
        settings["external_credentials_file"] = None


    # Other settings
    if "project_id_map" in user_data:
        settings["project_id_map"] = user_data["project_id_map"] or {}
    if "min_credentials" in user_data:
        settings["min_credentials"] = int(user_data["min_credentials"])
    if "log_level" in user_data:
        settings["log_level"] = user_data["log_level"]

    # Nested dictionaries
    timeouts_in = user_data.get("request_timeouts", {})
    if timeouts_in:
        settings["request_timeouts"]["connect"] = timeouts_in.get("connect", default_settings["request_timeouts"]["connect"])
        settings["request_timeouts"]["read"] = timeouts_in.get("read", default_settings["request_timeouts"]["read"])

    usage_in = user_data.get("usage_logging", {})
    if usage_in:
        settings["usage_logging"]["enabled"] = usage_in.get("enabled", default_settings["usage_logging"]["enabled"])
        settings["usage_logging"]["interval_sec"] = usage_in.get("interval_sec", default_settings["usage_logging"]["interval_sec"])

    return settings


def load_settings(config_path: str) -> SettingsDict:
    """从指定路径读取配置文件，与默认值合并并归一化路径。"""
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _normalize_settings(data)
