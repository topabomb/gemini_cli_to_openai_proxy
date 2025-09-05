"""
OpenAI 与 Google Gemini API 数据格式转换器模块。

此模块提供了在 OpenAI API 格式和 Google Gemini API 格式之间进行请求和响应数据转换的功能。
它使得本代理服务器能够兼容 OpenAI 的客户端库和工具链，同时与 Google 的 Gemini 模型进行交互。

主要功能包括：
1. `openai_request_to_gemini`: 将 OpenAI 的聊天补全请求转换为 Gemini API 所需的格式，
   包括消息内容、生成配置（如 temperature, max_tokens）、工具（如 Google Search）和思考配置。
2. `gemini_response_to_openai`: 将 Gemini API 的非流式响应转换为 OpenAI 的聊天补全响应格式，
   包括消息内容、推理内容（reasoning_content）和结束原因（finish_reason）。
3. `gemini_stream_chunk_to_openai`: 将 Gemini API 的流式响应块（SSE）转换为 OpenAI 的流式响应块格式。
"""

import json
import logging
import re
import time
import uuid
from typing import Dict, Any, Optional, cast

from .config import (
    DEFAULT_SAFETY_SETTINGS,
    is_search_model,
    get_base_model_name,
    get_thinking_budget,
    should_include_thoughts,
)


def openai_request_to_gemini(openai_request) -> Dict[str, Any]:
    """
    将 OpenAI 格式的聊天补全请求转换为 Google Gemini API 所需的请求格式。

    此函数会处理以下转换：
    1. 消息角色映射：OpenAI 的 "assistant" 映射为 Gemini 的 "model"。
    2. System 消息处理：将 OpenAI 的 "system" 消息抽取到 Gemini 的 "systemInstruction" 字段。
    3. 消息内容：支持文本和 base64 编码的图片 URL。
    4. 生成配置：将 OpenAI 的参数（如 temperature, max_tokens 等）映射到 Gemini 的 generationConfig。
    5. 模型变体：根据模型名称（如 -search, -nothinking）添加相应的工具和思考配置。

    Args:
        openai_request: 一个类似 OpenAI 请求结构的对象，应包含 messages, model, temperature 等属性。

    Returns:
        Dict[str, Any]: 一个符合 Google Gemini API 规范的请求负载字典。
    """
    contents = []
    system_messages = []

    # 转换消息内容和角色
    for message in openai_request.messages:
        role = message.role
        if role == "assistant":
            role = "model"
        elif role == "system":
            # 收集所有 system 消息
            if isinstance(message.content, str):
                system_messages.append(message.content)
            continue  # 不将 system 消息添加到 contents

        if isinstance(message.content, list):
            # 处理多模态内容（文本和图片）
            parts = []
            for part in message.content:
                # Pydantic 模型使用属性访问
                if part.type == "text":
                    parts.append({"text": getattr(part, 'text', "")})
                elif part.type == "image_url":
                    image_url = getattr(part.image_url, 'url', None) if part.image_url else None
                    if image_url:
                        # 使用正则表达式解析 base64 图片 URL，更健壮
                        match = re.match(r"data:(?P<mime_type>.*?);base64,(?P<data>.*)", image_url)
                        if match:
                            mime_type = match.group("mime_type")
                            base64_data = match.group("data")
                            parts.append(
                                {
                                    "inlineData": {
                                        "mimeType": mime_type,
                                        "data": base64_data,
                                    }
                                }
                            )
                        else:
                            logging.warning(f"Skipping malformed image_url data URI: {image_url[:100]}...")
                            continue
            contents.append({"role": role, "parts": parts})
        else:
            # 处理纯文本消息
            contents.append({"role": role, "parts": [{"text": message.content}]})

    # 转换生成配置参数
    generation_config = {}
    if openai_request.temperature is not None:
        generation_config["temperature"] = openai_request.temperature
    if openai_request.top_p is not None:
        generation_config["topP"] = openai_request.top_p
    if openai_request.max_tokens is not None:
        generation_config["maxOutputTokens"] = openai_request.max_tokens
    if openai_request.stop is not None:
        if isinstance(openai_request.stop, str):
            generation_config["stopSequences"] = [openai_request.stop]
        elif isinstance(openai_request.stop, list):
            generation_config["stopSequences"] = openai_request.stop
    if openai_request.frequency_penalty is not None:
        generation_config["frequencyPenalty"] = openai_request.frequency_penalty
    if openai_request.presence_penalty is not None:
        generation_config["presencePenalty"] = openai_request.presence_penalty
    if openai_request.n is not None:
        generation_config["candidateCount"] = openai_request.n
    if openai_request.seed is not None:
        generation_config["seed"] = openai_request.seed
    if openai_request.response_format is not None:
        # Pydantic 模型使用属性访问
        if getattr(openai_request.response_format, 'type', None) == "json_object":
            generation_config["responseMimeType"] = "application/json"

    # 构建基础请求负载
    request_payload = {
        "contents": contents,
        "generationConfig": generation_config,
        "safetySettings": DEFAULT_SAFETY_SETTINGS,
    }

    # 如果有 system 消息，则合并并添加到请求负载
    if system_messages:
        request_payload["systemInstruction"] = {"parts": [{"text": "\n".join(system_messages)}]}

    # 为 search 模型变体添加 Google Search 工具
    if is_search_model(openai_request.model):
        request_payload["tools"] = [{"googleSearch": {}}]

    # 为模型添加 thinking 配置
    thinking_budget = get_thinking_budget(openai_request.model)
    if thinking_budget is not None:
        request_payload["generationConfig"]["thinkingConfig"] = {
            "thinkingBudget": thinking_budget,
            "includeThoughts": should_include_thoughts(openai_request.model),
        }

    return request_payload


def gemini_response_to_openai(
    gemini_response: Dict[str, Any], model: str
) -> Dict[str, Any]:
    """
    将 Google Gemini API 的非流式响应转换为 OpenAI 聊天补全响应格式。

    此函数会处理以下转换：
    1. 候选内容（candidates）：将 Gemini 的候选内容列表转换为 OpenAI 的 choices 列表。
    2. 消息角色映射：Gemini 的 "model" 角色映射为 OpenAI 的 "assistant"。
    3. 内容提取：从 parts 中提取文本内容和推理内容（reasoning_content）。
    4. 结束原因映射：将 Gemini 的 finishReason 映射为 OpenAI 的 finish_reason。

    Args:
        gemini_response (Dict[str, Any]): 来自 Google Gemini API 的非流式响应 JSON 对象。
        model (str): 原始请求中使用的模型名称。

    Returns:
        Dict[str, Any]: 一个符合 OpenAI 聊天补全响应格式的字典。
    """
    choices = []
    # 遍历所有候选响应
    for candidate in gemini_response.get("candidates", []):
        # 处理角色映射
        role = candidate.get("content", {}).get("role", "assistant")
        if role == "model":
            role = "assistant"

        # 提取内容和推理内容
        parts = candidate.get("content", {}).get("parts", [])
        content = ""
        reasoning_content = ""
        for part in parts:
            if not part.get("text"):
                continue
            # 根据 'thought' 标记区分普通内容和推理内容
            if part.get("thought", False):
                reasoning_content += part.get("text", "")
            else:
                content += part.get("text", "")

        # 构建 OpenAI 格式的 message 对象
        message = {"role": role, "content": content}
        if reasoning_content:
            message["reasoning_content"] = reasoning_content

        # 构建 choice 对象并添加到列表
        choices.append(
            {
                "index": candidate.get("index", 0),
                "message": message,
                "finish_reason": _map_finish_reason(candidate.get("finishReason")),
            }
        )

    # 构建并返回最终的 OpenAI 响应
    return {
        "id": str(uuid.uuid4()),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": choices,
    }


def gemini_stream_chunk_to_openai(
    gemini_chunk: Dict[str, Any], model: str, response_id: str
) -> Dict[str, Any]:
    """
    将 Google Gemini API 的流式响应块（SSE）转换为 OpenAI 流式响应块格式。

    此函数与 `gemini_response_to_openai` 类似，但处理的是流式数据块，并生成 OpenAI 的 "chat.completion.chunk" 对象。

    Args:
        gemini_chunk (Dict[str, Any]): 来自 Google Gemini API 的单个流式响应块（JSON 对象）。
        model (str): 原始请求中使用的模型名称。
        response_id (str): 为整个流式响应生成的唯一 ID，在流式传输期间保持不变。

    Returns:
        Dict[str, Any]: 一个符合 OpenAI 流式响应块格式的字典。
    """
    choices = []
    # 遍历块中的候选内容
    for candidate in gemini_chunk.get("candidates", []):
        # 处理角色映射
        role = candidate.get("content", {}).get("role", "assistant")
        if role == "model":
            role = "assistant"

        # 提取内容和推理内容
        parts = candidate.get("content", {}).get("parts", [])
        content = ""
        reasoning_content = ""
        for part in parts:
            if not part.get("text"):
                continue
            # 根据 'thought' 标记区分普通内容和推理内容
            if part.get("thought", False):
                reasoning_content += part.get("text", "")
            else:
                content += part.get("text", "")

        # 构建 OpenAI 格式的 delta 对象
        delta = {}
        if content:
            delta["content"] = content
        if reasoning_content:
            delta["reasoning_content"] = reasoning_content

        # 构建 choice 对象并添加到列表
        choices.append(
            {
                "index": candidate.get("index", 0),
                "delta": delta,
                "finish_reason": _map_finish_reason(candidate.get("finishReason")),
            }
        )

    # 构建并返回最终的 OpenAI 流式响应块
    return {
        "id": response_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": choices,
    }


def _map_finish_reason(gemini_reason: str) -> Optional[str]:
    """
    将 Google Gemini API 的结束原因映射为 OpenAI API 的结束原因。

    Args:
        gemini_reason (str): 来自 Gemini API 的结束原因字符串。

    Returns:
        str: 对应的 OpenAI API 结束原因字符串，如果无法映射则返回 None。
    """
    if gemini_reason == "STOP":
        # Gemini 的 "STOP" 对应 OpenAI 的 "stop" (自然结束)
        return "stop"
    elif gemini_reason == "MAX_TOKENS":
        # Gemini 的 "MAX_TOKENS" 对应 OpenAI 的 "length" (达到最大长度)
        return "length"
    elif gemini_reason in ["SAFETY", "RECITATION"]:
        # Gemini 的 "SAFETY" 或 "RECITATION" 对应 OpenAI 的 "content_filter" (内容被过滤)
        return "content_filter"
    else:
        # 对于其他未知的结束原因，返回 None
        return None


def build_gemini_payload_from_native(
    native_request: dict, model_from_path: str
) -> dict:
    """
    将原生 Google Gemini API 请求负载进行处理，以支持模型变体（如 -search, -nothinking）和默认安全设置。

    Args:
        native_request (dict): 来自原生 Gemini API 的请求负载。
        model_from_path (str): 从请求 URL 路径中提取的模型名称（可能包含变体后缀）。

    Returns:
        dict: 处理后的请求负载字典，包含 'model' (基础模型名) 和 'request' 键。
    """
    # 应用默认安全设置
    native_request["safetySettings"] = DEFAULT_SAFETY_SETTINGS

    # 确保 generationConfig 存在
    if "generationConfig" not in native_request:
        native_request["generationConfig"] = {}

    # 处理 thinking 相关配置
    if "thinkingConfig" not in native_request["generationConfig"]:
        native_request["generationConfig"]["thinkingConfig"] = {}

    thinking_budget = get_thinking_budget(model_from_path)
    include_thoughts = should_include_thoughts(model_from_path)

    native_request["generationConfig"]["thinkingConfig"][
        "includeThoughts"
    ] = include_thoughts

    # 如果模型变体指定了 thinkingBudget，则应用它
    if (
        "thinkingBudget" in native_request["generationConfig"]["thinkingConfig"]
        and thinking_budget == -1
    ):
        pass  # 保持用户提供的值
    else:
        native_request["generationConfig"]["thinkingConfig"][
            "thinkingBudget"
        ] = thinking_budget

    # 如果是 search 模型变体，则添加 Google Search 工具
    if is_search_model(model_from_path):
        if "tools" not in native_request:
            native_request["tools"] = []
        if not any(tool.get("googleSearch") for tool in native_request["tools"]):
            native_request["tools"].append({"googleSearch": {}})

    # 返回基础模型名和处理后的请求体
    return {"model": get_base_model_name(model_from_path), "request": native_request}
