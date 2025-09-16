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
    
    # 修正: 从 gemini_response['response']['candidates'] 获取
    response_obj = gemini_response.get("response", {})
    
    for candidate in response_obj.get("candidates", []):
        # 关键修复: 过滤掉 Gemini 返回的 "thought" 部分。
        # 背景: Gemini API 可能会在返回最终答案前，先输出一个包含其 "思考过程" 的 part，其 `thought` 字段为 true。
        # 问题: 如果不加过滤，这个思考过程会和最终答案拼接在一起，导致客户端（如 ChatGPT Next Web）收到非预期的内容而报错。
        # 方案: 我们只选择那些 `thought` 字段不存在或为 False 的 part，以确保只包含最终的模型输出。
        text_parts = [
            part.get("text", "")
            for part in candidate.get("content", {}).get("parts", [])
            if not part.get("thought")
        ]
        content = "".join(text_parts)
        
        message = {"role": "assistant", "content": content}
        choices.append({
            "index": candidate.get("index", 0),
            "message": message,
            "finish_reason": _map_finish_reason(candidate.get("finishReason")),
        })

    # 如果 choices 为空，则根据 promptFeedback 创建一个默认的 choice
    if not choices:
        finish_reason = None
        prompt_feedback = response_obj.get("promptFeedback") # 修正: 从 response_obj 获取
        if prompt_feedback:
            # 从 blockReason 映射 finish_reason
            block_reason = prompt_feedback.get("blockReason")
            if block_reason == "SAFETY":
                finish_reason = "content_filter"
            # 可以根据需要添加其他 blockReason 的映射

        choices.append({
            "index": 0,
            "message": {"role": "assistant", "content": None},
            "finish_reason": finish_reason,
        })

    # 模拟 usage 对象
    usage_metadata = response_obj.get("usageMetadata", {}) # 修正: 从 response_obj 获取
    usage = {
        "prompt_tokens": usage_metadata.get("promptTokenCount", 0),
        "completion_tokens": usage_metadata.get("candidatesTokenCount", 0),
        "total_tokens": usage_metadata.get("totalTokenCount", 0),
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
        
        # 关键修复: 统一并加固对 "thought" 部分的过滤逻辑。
        # 背景: 与非流式响应一样，流式响应的每个数据块（chunk）也可能包含 `thought` part。
        # 问题: 虽然流式传输对 `thought` 有天然的容错能力（客户端会忽略空块），但保持与非流式代码一致的、更健壮的过滤逻辑是良好的工程实践。
        # 方案: 采用 `not part.get("thought")` 的方式，可以正确处理 `thought` 字段不存在、为 None 或为 False 的所有情况。
        text_parts = [
            part.get("text", "")
            for part in candidate.get("content", {}).get("parts", [])
            if not part.get("thought")
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
    将 OpenAI 格式的聊天补全请求转换为 Google Gemini API 所需的请求格式，并合并连续的用户消息。
    """
    contents = []
    system_instruction = None

    for message in openai_request.get("messages", []):
        role = message.get("role")
        
        if role == "system":
            system_content = message.get("content", "")
            if isinstance(system_content, str):
                system_instruction = {"parts": [{"text": system_content}]}
            continue

        gemini_role = "model" if role == "assistant" else "user"

        content = message.get("content")
        current_parts = []
        if isinstance(content, str):
            current_parts.append({"text": content})
        elif isinstance(content, list):
            for part in content:
                if part.get("type") == "text":
                    current_parts.append({"text": part.get("text", "")})
                elif part.get("type") == "image_url":
                    image_url = part.get("image_url", {}).get("url", "")
                    match = re.match(r"data:(?P<mime_type>.*?);base64,(?P<data>.*)", image_url)
                    if match:
                        current_parts.append({"inlineData": {"mimeType": match.group("mime_type"), "data": match.group("data")}})
        
        if contents and contents[-1]["role"] == "user" and gemini_role == "user":
            if contents[-1]["parts"] and isinstance(contents[-1]["parts"][-1].get("text"), str):
                 contents[-1]["parts"].append({"text": "\n"})
            contents[-1]["parts"].extend(current_parts)
        else:
            contents.append({"role": gemini_role, "parts": current_parts})

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
