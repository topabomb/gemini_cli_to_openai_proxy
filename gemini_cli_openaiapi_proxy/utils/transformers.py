"""
数据格式转换工具模块：
- 负责在 OpenAI API 格式和 Google Gemini API 格式之间进行数据转换。
- 包含处理模型名称变体的辅助函数。
"""

import base64
import logging
import time
import uuid
import re
from typing import Dict, Any, List, Optional

from ..core.models import (
    get_base_model_name,
    is_search_model,
    get_thinking_budget,
    should_include_thoughts,
)

# ===== Gemini to OpenAI 转换 =====

def _map_finish_reason(gemini_reason: str) -> Optional[str]:
    """将 Gemini 的结束原因映射为 OpenAI 的结束原因。"""
    if gemini_reason == "STOP":
        return "stop"
    elif gemini_reason == "MAX_TOKENS":
        return "length"
    elif gemini_reason in ["SAFETY", "RECITATION"]:
        return "content_filter"
    else:
        return None

def gemini_to_openai_response(gemini_response: Dict[str, Any], model: str) -> Dict[str, Any]:
    """将 Gemini 的非流式响应转换为 OpenAI 聊天补全响应格式。"""
    choices = []
    for candidate in gemini_response.get("candidates", []):
        content = "".join(part.get("text", "") for part in candidate.get("content", {}).get("parts", []))
        message = {"role": "assistant", "content": content}
        choices.append({
            "index": candidate.get("index", 0),
            "message": message,
            "finish_reason": _map_finish_reason(candidate.get("finishReason")),
        })
    
    # 模拟 usage 对象
    usage = {
        "prompt_tokens": gemini_response.get("usageMetadata", {}).get("promptTokenCount", 0),
        "completion_tokens": gemini_response.get("usageMetadata", {}).get("candidatesTokenCount", 0),
        "total_tokens": gemini_response.get("usageMetadata", {}).get("totalTokenCount", 0),
    }

    return {
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": choices,
        "usage": usage,
    }

def gemini_to_openai_stream_chunk(gemini_chunk: Dict[str, Any], model: str, response_id: str, is_first_chunk: bool) -> Dict[str, Any]:
    """将 Gemini 的流式块转换为 OpenAI 的流式块。"""
    choices = []
    response_obj = gemini_chunk.get("response", {})
    for candidate in response_obj.get("candidates", []):
        delta = {}
        
        # 过滤掉 "thought" part
        text_parts = [
            part.get("text", "")
            for part in candidate.get("content", {}).get("parts", [])
            if "thought" not in part
        ]
        content = "".join(text_parts)

        if content:
            delta["content"] = content
        
        # 在流的第一个块中设置角色
        if is_first_chunk:
            delta["role"] = "assistant"

        choices.append({
            "index": candidate.get("index", 0),
            "delta": delta,
            "finish_reason": _map_finish_reason(candidate.get("finishReason")),
        })

    return {
        "id": response_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": choices,
    }

# ===== OpenAI to Gemini 转换 =====

def openai_to_gemini_request(openai_request: Dict[str, Any]) -> Dict[str, Any]:
    """
    将 OpenAI 格式的聊天补全请求转换为 Google Gemini API 所需的请求格式。
    """
    contents = []
    system_instruction = None

    for message in openai_request.get("messages", []):
        role = message.get("role")
        if role == "assistant":
            role = "model"
        elif role == "system":
            system_instruction = {"parts": [{"text": message.get("content", "")}]}
            continue

        content = message.get("content")
        parts = []
        if isinstance(content, str):
            parts.append({"text": content})
        elif isinstance(content, list):
            for part in content:
                if part.get("type") == "text":
                    parts.append({"text": part.get("text", "")})
                elif part.get("type") == "image_url":
                    image_url = part.get("image_url", {}).get("url", "")
                    match = re.match(r"data:(?P<mime_type>.*?);base64,(?P<data>.*)", image_url)
                    if match:
                        parts.append({"inlineData": {"mimeType": match.group("mime_type"), "data": match.group("data")}})

        contents.append({"role": role, "parts": parts})

    generation_config = {}
    if "temperature" in openai_request:
        generation_config["temperature"] = openai_request["temperature"]
    if "top_p" in openai_request:
        generation_config["topP"] = openai_request["top_p"]
    if "max_tokens" in openai_request:
        generation_config["maxOutputTokens"] = openai_request["max_tokens"]
    if "stop" in openai_request:
        generation_config["stopSequences"] = openai_request["stop"] if isinstance(openai_request["stop"], list) else [openai_request["stop"]]
    if "n" in openai_request:
        generation_config["candidateCount"] = openai_request["n"]

    request_payload = {
        "contents": contents,
        "generationConfig": generation_config,
    }

    if system_instruction:
        request_payload["systemInstruction"] = system_instruction

    return build_gemini_payload_from_native(request_payload, openai_request.get("model", ""))

def build_gemini_payload_from_native(
    native_request: dict, model_from_path: str
) -> dict:
    """
    将原生 Google Gemini API 请求负载进行处理，以支持模型变体和默认安全设置。
    """
    from ..core.config import DEFAULT_SAFETY_SETTINGS

    request = native_request
    if "safetySettings" not in request:
        request["safetySettings"] = DEFAULT_SAFETY_SETTINGS

    if "generationConfig" not in request:
        request["generationConfig"] = {}

    if "thinkingConfig" not in request["generationConfig"]:
        request["generationConfig"]["thinkingConfig"] = {}

    thinking_budget = get_thinking_budget(model_from_path)
    include_thoughts = should_include_thoughts(model_from_path)
    
    if "includeThoughts" not in request["generationConfig"]["thinkingConfig"]:
        request["generationConfig"]["thinkingConfig"]["includeThoughts"] = include_thoughts

    if "thinkingBudget" not in request["generationConfig"]["thinkingConfig"]:
        if thinking_budget != -1:
            request["generationConfig"]["thinkingConfig"]["thinkingBudget"] = thinking_budget
    
    if not request["generationConfig"]["thinkingConfig"]:
        del request["generationConfig"]["thinkingConfig"]

    if is_search_model(model_from_path):
        if "tools" not in request:
            request["tools"] = []
        if not any("google_search" in tool for tool in request.get("tools", [])):
            request["tools"].append({"google_search": {}})

    return {"model": get_base_model_name(model_from_path), "request": request}
