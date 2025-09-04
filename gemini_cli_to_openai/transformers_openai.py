"""
OpenAI 与 Gemini 转换器，迁移自 src/openai_transformers.py。
"""
import json
import time
import uuid
from typing import Dict, Any

from .config import (
    DEFAULT_SAFETY_SETTINGS,
    is_search_model,
    get_base_model_name,
    get_thinking_budget,
    should_include_thoughts,
)


def openai_request_to_gemini(openai_request) -> Dict[str, Any]:
    """将 OpenAI 请求转为 Gemini 请求。"""
    contents = []

    for message in openai_request.messages:
        role = message.role
        if role == "assistant":
            role = "model"
        elif role == "system":
            role = "user"

        if isinstance(message.content, list):
            parts = []
            for part in message.content:
                if part.get("type") == "text":
                    parts.append({"text": part.get("text", "")})
                elif part.get("type") == "image_url":
                    image_url = part.get("image_url", {}).get("url")
                    if image_url:
                        try:
                            mime_type, base64_data = image_url.split(";")
                            _, mime_type = mime_type.split(":")
                            _, base64_data = base64_data.split(",")
                            parts.append({
                                "inlineData": {
                                    "mimeType": mime_type,
                                    "data": base64_data,
                                }
                            })
                        except ValueError:
                            continue
            contents.append({"role": role, "parts": parts})
        else:
            contents.append({"role": role, "parts": [{"text": message.content}]})

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
        if openai_request.response_format.get("type") == "json_object":
            generation_config["responseMimeType"] = "application/json"

    request_payload = {
        "contents": contents,
        "generationConfig": generation_config,
        "safetySettings": DEFAULT_SAFETY_SETTINGS,
        "model": get_base_model_name(openai_request.model),
    }

    if is_search_model(openai_request.model):
        request_payload["tools"] = [{"googleSearch": {}}]

    thinking_budget = get_thinking_budget(openai_request.model)
    if thinking_budget is not None:
        request_payload["generationConfig"]["thinkingConfig"] = {
            "thinkingBudget": thinking_budget,
            "includeThoughts": should_include_thoughts(openai_request.model),
        }

    return request_payload


def gemini_response_to_openai(gemini_response: Dict[str, Any], model: str) -> Dict[str, Any]:
    """将 Gemini 非流式响应转为 OpenAI 格式。"""
    choices = []
    for candidate in gemini_response.get("candidates", []):
        role = candidate.get("content", {}).get("role", "assistant")
        if role == "model":
            role = "assistant"

        parts = candidate.get("content", {}).get("parts", [])
        content = ""
        reasoning_content = ""
        for part in parts:
            if not part.get("text"):
                continue
            if part.get("thought", False):
                reasoning_content += part.get("text", "")
            else:
                content += part.get("text", "")

        message = {"role": role, "content": content}
        if reasoning_content:
            message["reasoning_content"] = reasoning_content

        choices.append({
            "index": candidate.get("index", 0),
            "message": message,
            "finish_reason": _map_finish_reason(candidate.get("finishReason")),
        })

    return {
        "id": str(uuid.uuid4()),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": choices,
    }


def gemini_stream_chunk_to_openai(gemini_chunk: Dict[str, Any], model: str, response_id: str) -> Dict[str, Any]:
    """将 Gemini 流式分块转为 OpenAI SSE 分块。"""
    choices = []
    for candidate in gemini_chunk.get("candidates", []):
        role = candidate.get("content", {}).get("role", "assistant")
        if role == "model":
            role = "assistant"

        parts = candidate.get("content", {}).get("parts", [])
        content = ""
        reasoning_content = ""
        for part in parts:
            if not part.get("text"):
                continue
            if part.get("thought", False):
                reasoning_content += part.get("text", "")
            else:
                content += part.get("text", "")

        delta = {}
        if content:
            delta["content"] = content
        if reasoning_content:
            delta["reasoning_content"] = reasoning_content

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


def _map_finish_reason(gemini_reason: str) -> str:
    if gemini_reason == "STOP":
        return "stop"
    elif gemini_reason == "MAX_TOKENS":
        return "length"
    elif gemini_reason in ["SAFETY", "RECITATION"]:
        return "content_filter"
    else:
        return None


