"""
模型定义与辅助函数模块。

- 定义了所有支持的 Gemini 基础模型及其属性。
- 动态生成模型的变体（如 -search, -nothinking, -maxthinking）。
- 提供用于解析模型名称和获取模型特定配置的辅助函数。
"""

# ===== 模型常量定义 =====

BASE_MODELS = [
    {
        "name": "models/gemini-flash-latest",
        "version": "001",
        "displayName": "Gemini Flash Latest",
        "description": "Fast and efficient multimodal model with latest improvements",
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
    
]


def _generate_variants(base_models):
    """根据基础模型生成所有变体。"""
    variants = []
    for model in base_models:
        if "generateContent" in model["supportedGenerationMethods"]:
            # Search Variant
            search_variant = model.copy()
            search_variant["name"] = model["name"] + "-search"
            search_variant["displayName"] = model["displayName"] + " with Google Search"
            variants.append(search_variant)

            # Thinking Variants
            if "gemini-2.5" in model["name"]:
                nt = model.copy()
                nt["name"] = model["name"] + "-nothinking"
                nt["displayName"] = model["displayName"] + " (No Thinking)"
                variants.append(nt)

                mt = model.copy()
                mt["name"] = model["name"] + "-maxthinking"
                mt["displayName"] = model["displayName"] + " (Max Thinking)"
                variants.append(mt)
    return variants


SUPPORTED_MODELS = sorted(BASE_MODELS + _generate_variants(BASE_MODELS), key=lambda x: x["name"])


# ===== 模型名称处理辅助函数 =====

def get_base_model_name(model_name: str) -> str:
    """
    从模型名称中移除变体后缀（如 -search, -nothinking）。
    
    示例:
        "models/gemini-2.5-pro-search" -> "models/gemini-2.5-pro"
    """
    suffixes = ["-search", "-nothinking", "-maxthinking"]
    for s in suffixes:
        if model_name.endswith(s):
            return model_name[: -len(s)]
    return model_name

def is_search_model(model_name: str) -> bool:
    """检查模型名称是否为 'search' 变体。"""
    return "-search" in model_name

def is_nothinking_model(model_name: str) -> bool:
    """检查模型名称是否为 'nothinking' 变体。"""
    return "-nothinking" in model_name

def is_maxthinking_model(model_name: str) -> bool:
    """检查模型名称是否为 'maxthinking' 变体。"""
    return "-maxthinking" in model_name

def get_thinking_budget(model_name: str) -> int:
    """
    根据模型名称获取其 'thinking' 预算。
    
    返回:
        - 0: 对于 'nothinking' 变体。
        - 24576: 对于 'gemini-2.5-flash-maxthinking'。
        - 32768: 对于 'gemini-2.5-pro-maxthinking'。
        - -1: 表示使用 API 默认值（在请求中不应包含此字段）。
    """
    base_model = get_base_model_name(model_name)
    if is_nothinking_model(model_name):
        return 0
    elif is_maxthinking_model(model_name):
        if "gemini-2.5-flash" in base_model:
            return 24576
        elif "gemini-2.5-pro" in base_model:
            return 32768
    return -1

def should_include_thoughts(model_name: str) -> bool:
    """
    判断是否应在请求中包含 'thoughts'。
    'nothinking' 变体通常不包含，但 'pro' 模型是一个例外。
    """
    if is_nothinking_model(model_name):
        base_model = get_base_model_name(model_name)
        return "gemini-2.5-pro" in base_model
    return True
