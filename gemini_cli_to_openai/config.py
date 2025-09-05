"""
配置模块：
- 提供 `default_settings`（无入参时使用的默认配置）。
- 提供 `load_settings(config_path)`：从指定 JSON 文件加载并与默认值合并，路径归一化。
- 提供硬编码的 OAuth 客户端常量与模型常量（从原 src/config.py 迁移）。
- 仅使用配置/参数驱动，不读取环境变量。
"""
import json
import os
from typing import Any, Dict, List, Optional


# ===== 硬编码 OAuth 配置 =====
CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"# Google OAuth 2.0 客户端 ID (Client ID)
CLIENT_SECRET = "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" # Google OAuth 2.0 客户端密钥 (Client Secret)
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


# ===== 模型常量与帮助函数（从 src/config.py 迁移） =====
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
            search_variant["description"] = model["description"] + " (includes Google Search grounding)"
            search_models.append(search_variant)
    return search_models


def _generate_thinking_variants():
    """根据基础模型生成 -nothinking 与 -maxthinking 变体。"""
    thinking_models = []
    for model in BASE_MODELS:
        if ("generateContent" in model["supportedGenerationMethods"] and
            ("gemini-2.5-flash" in model["name"] or "gemini-2.5-pro" in model["name"])):
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


def _make_default_settings() -> Dict[str, Any]:
    """生成默认配置（含路径归一化）。"""
    data: Dict[str, Any] = {
        "server": {"host": "0.0.0.0", "port": 8888},
        "auth_password": "123456",
        "credentials_file": "credentials.json",
        "external_credentials_file": None,
        "project_id_map": {},
        "min_credentials": 1,
        "log_level": "INFO",
    }
    # 归一化路径
    data["credentials_file"] = _abspath(data["credentials_file"])  # type: ignore
    data["external_credentials_file"] = _abspath(data.get("external_credentials_file"))  # type: ignore
    return data


default_settings: Dict[str, Any] = _make_default_settings()


def _normalize_settings(data: Dict[str, Any]) -> Dict[str, Any]:
    """与默认配置合并并做路径归一化与基本校验。"""
    result = dict(default_settings)
    result.update(data or {})

    # server 合并与校正类型
    server_default = default_settings.get("server", {})
    server_in = result.get("server", {}) or {}
    host = server_in.get("host", server_default.get("host", "0.0.0.0"))
    port = int(server_in.get("port", server_default.get("port", 8888)))
    result["server"] = {"host": host, "port": port}

    # 路径归一化
    result["credentials_file"] = _abspath(result.get("credentials_file"))
    if result.get("external_credentials_file"):
        result["external_credentials_file"] = _abspath(result.get("external_credentials_file"))
    else:
        result["external_credentials_file"] = None

    # 其他默认
    result["auth_password"] = result.get("auth_password", default_settings["auth_password"])  # type: ignore
    result["project_id_map"] = result.get("project_id_map", {}) or {}
    result["min_credentials"] = int(result.get("min_credentials", default_settings["min_credentials"]))  # type: ignore
    result["log_level"] = result.get("log_level", default_settings["log_level"])  # type: ignore

    return result


def load_settings(config_path: str) -> Dict[str, Any]:
    """从指定路径读取配置文件，与默认值合并并归一化路径。"""
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _normalize_settings(data)


