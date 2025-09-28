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
import httpx
import mimetypes
from typing import Dict, Any, List, Optional

from ..core.models import (
    get_base_model_name,
    is_search_model,
    get_thinking_budget,
    should_include_thoughts,
)

# ===== Gemini to OpenAI 转换 =====

def _map_finish_reason(gemini_reason: Optional[str]) -> Optional[str]:
    """将 Gemini 的结束原因映射为 OpenAI 的结束原因。"""
    # 在流式传输中，中间的块没有 finishReason，所以 gemini_reason 可能为 None
    if not gemini_reason:
        return None
        
    if gemini_reason == "STOP":
        return "stop"
    elif gemini_reason == "MAX_TOKENS":
        return "length"
    elif gemini_reason in ["SAFETY", "RECITATION", "BLOCKED", "PROHIBITED"]:
        return "content_filter"
    else:
        # 仅当收到一个非空但不认识的原因时才发出警告
        logging.warning(f"Unknown Gemini finish reason: {gemini_reason}, mapping to None")
        return None

def gemini_to_openai_response(gemini_response: Dict[str, Any], model: str, filter_thoughts: bool = True) -> Dict[str, Any]:
    """将 Gemini 的非流式响应转换为 OpenAI 聊天补全响应格式。

    Args:
        gemini_response: Gemini API 响应
        model: 模型名称
        filter_thoughts: 是否过滤 'thought' 部分，默认 True 以兼容旧客户端
    """
    choices = []

    # 修正: 从 gemini_response['response']['candidates'] 获取
    response_obj = gemini_response.get("response", {})

    for candidate in response_obj.get("candidates", []):
        content = ""
        reasoning_content = ""

        for part in candidate.get("content", {}).get("parts", []):
            text = part.get("text", "")
            is_thought = part.get("thought", False)

            if filter_thoughts:
                # 增强检测：只过滤 thought=True 且有内容的
                if is_thought and text.strip():
                    logging.info(f"Filtering thought part in candidate {candidate.get('index', 0)} for model {model}")
                    continue
                content += text
            else:
                # 提取 thought 为 reasoning_content
                if is_thought and text.strip():
                    reasoning_content += text
                else:
                    content += text

        message = {"role": "assistant", "content": content}
        if reasoning_content:
            message["reasoning_content"] = reasoning_content

        choices.append({
            "index": candidate.get("index", 0),
            "message": message,
            "finish_reason": _map_finish_reason(candidate.get("finishReason")),
        })

    # 如果 choices 为空，返回错误而不是创建默认 choice
    if not choices:
        logging.error(f"No valid candidates in Gemini response for model {model}. Response: {gemini_response}")
        raise ValueError("No valid candidates in Gemini response")

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

def gemini_to_openai_stream_chunk(gemini_chunk: Dict[str, Any], model: str, response_id: str, is_first_chunk: bool, filter_thoughts: bool = True) -> Dict[str, Any]:
    """将 Gemini 的流式块转换为 OpenAI 的流式块。

    Args:
        gemini_chunk: Gemini 流式块
        model: 模型名称
        response_id: 响应 ID
        is_first_chunk: 是否为第一个块
        filter_thoughts: 是否过滤 'thought' 部分，默认 True
    """
    choices = []
    response_obj = gemini_chunk.get("response", {})
    for candidate in response_obj.get("candidates", []):
        delta = {}
        content = ""
        reasoning_content = ""

        for part in candidate.get("content", {}).get("parts", []):
            text = part.get("text", "")
            is_thought = part.get("thought", False)

            if filter_thoughts:
                # 增强检测：只过滤 thought=True 且有内容的
                if is_thought and text.strip():
                    logging.info(f"Filtering thought part in stream chunk for candidate {candidate.get('index', 0)} model {model}")
                    continue
                content += text
            else:
                # 提取 thought 为 reasoning_content
                if is_thought and text.strip():
                    reasoning_content += text
                else:
                    content += text

        if content:
            delta["content"] = content
        if reasoning_content:
            delta["reasoning_content"] = reasoning_content

        # 在流的第一个块中设置角色
        if is_first_chunk:
            delta["role"] = "assistant"

        # 过滤空 delta
        if not delta and not _map_finish_reason(candidate.get("finishReason")):
            continue

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

async def openai_to_gemini_request(openai_request: Dict[str, Any]) -> Dict[str, Any]:
    """
    将 OpenAI 格式的聊天补全请求转换为 Google Gemini API 所需的请求格式，并合并连续的用户消息。
    """
    model = openai_request.get("model", "")
    from ..core.models import SUPPORTED_MODELS
    supported_model_names = [m["name"].replace("models/", "") for m in SUPPORTED_MODELS]
    if model not in supported_model_names:
        logging.error(f"Unsupported model: {model}. Supported models: {supported_model_names}")
        raise ValueError(f"Unsupported model: {model}")
    contents = []
    system_instruction = None

    for message in openai_request.get("messages", []):
        role = message.get("role")

        if role == "system":
            system_content = message.get("content", "")
            if isinstance(system_content, str):
                if system_instruction:
                    # 如果已有 system_instruction，合并内容
                    system_instruction["parts"][0]["text"] += "\n---\n" + system_content
                    logging.info("Merged multiple system messages")
                else:
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
                    
                    if image_url.startswith("data:"):
                        # 加固的正则表达式，允许MIME类型和base64声明之间有空格
                        match = re.match(r"data:\s*(?P<mime_type>.*?)\s*;\s*base64\s*,(?P<data>.*)", image_url, re.DOTALL)
                        if match:
                            current_parts.append({"inlineData": {"mimeType": match.group("mime_type"), "data": match.group("data")}})
                        else:
                            # 从记录警告升级为抛出异常，为用户提供明确的反馈
                            raise ValueError(f"Invalid base64 image URL format: {image_url[:100]}...")
                    
                    elif image_url.startswith("http://") or image_url.startswith("https://"):
                        try:
                            async with httpx.AsyncClient() as client:
                                response = await client.get(image_url, follow_redirects=True, timeout=20.0)
                                response.raise_for_status()
                            
                            image_data = response.content
                            # 从响应头获取 mime_type，如果失败则从 URL 猜测
                            mime_type = response.headers.get("Content-Type")
                            if not mime_type:
                                mime_type = mimetypes.guess_type(image_url)[0]
                            
                            if not mime_type:
                                raise ValueError(f"Could not determine mime type for image URL: {image_url}")

                            encoded_data = base64.b64encode(image_data).decode("utf-8")
                            current_parts.append({"inlineData": {"mimeType": mime_type, "data": encoded_data}})

                        except httpx.HTTPStatusError as e:
                            raise ValueError(f"Failed to download image from {image_url}. Status: {e.response.status_code}")
                        except Exception as e:
                            raise ValueError(f"An error occurred while processing image URL {image_url}: {e}")
                    
                    else:
                        raise ValueError(f"Unsupported image URL format: {image_url[:100]}...")
        
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

    # 添加警告日志对于不完全映射的参数
    if "frequency_penalty" in openai_request:
        logging.warning("frequency_penalty is not fully supported in Gemini, using approximate mapping")
    if "presence_penalty" in openai_request:
        logging.warning("presence_penalty is not fully supported in Gemini, using approximate mapping")

    # 兼容 OpenAI 的 JSON 模式
    if openai_request.get("response_format", {}).get("type") == "json_object":
        generation_config["response_mime_type"] = "application/json"
        logging.info("JSON mode enabled for Gemini request by mapping response_format.")

    request_payload = {
        "contents": contents,
        "generationConfig": generation_config,
    }

    # 兼容 OpenAI 的 tool_choice
    tool_choice = openai_request.get("tool_choice")
    if tool_choice:
        function_calling_config = {}
        if isinstance(tool_choice, str):
            if tool_choice == "none":
                function_calling_config["mode"] = "NONE"
            elif tool_choice == "auto":
                function_calling_config["mode"] = "AUTO"
            elif tool_choice == "required":
                # "required" 在 OpenAI 中意味着必须调用一个工具，等同于 Gemini 的 "ANY"
                function_calling_config["mode"] = "ANY"
        elif isinstance(tool_choice, dict) and tool_choice.get("type") == "function":
            function_name = tool_choice.get("function", {}).get("name")
            if function_name:
                # 强制调用特定函数
                function_calling_config["mode"] = "ANY"
                function_calling_config["allowed_function_names"] = [function_name]

        if function_calling_config:
            # Gemini 的 toolConfig 是一个顶层参数
            request_payload["toolConfig"] = {"functionCallingConfig": function_calling_config}
            logging.info(f"Tool choice mapped to Gemini's toolConfig: {function_calling_config}")

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
