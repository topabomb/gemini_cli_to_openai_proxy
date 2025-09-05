"""
OpenAI 兼容路由：从 src/openai_routes.py 迁移，保持行为不变。
"""

import json
import uuid
import asyncio
import logging
from typing import Dict, Any, Union, cast, List, Optional
from fastapi import APIRouter, Request, Response, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .transformers_openai import (
    openai_request_to_gemini,
    gemini_response_to_openai,
    gemini_stream_chunk_to_openai,
)
from .client import ApiClient
from .auth import authenticate_request
from .state import api_client as api_client_state, settings as settings_state


router = APIRouter()


# Pydantic 模型用于请求体验证
class ChatMessageContentPart(BaseModel):
    type: str
    text: Optional[str] = None
    image_url: Optional[Dict[str, str]] = None

class ChatMessage(BaseModel):
    role: str
    content: Union[str, List[ChatMessageContentPart]]

class ResponseFormat(BaseModel):
    type: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    stream: bool = False
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    max_tokens: Optional[int] = None
    stop: Optional[Union[str, List[str]]] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    n: Optional[int] = None
    seed: Optional[int] = None
    response_format: Optional[ResponseFormat] = None


def _get_settings():
    # 由 app.py 注入全局 settings
    from .state import settings, api_client

    return settings, api_client


@router.post("/v1/chat/completions")
async def openai_chat_completions(
    request: Request,
    oa_req: ChatCompletionRequest,
):
    settings, api_client = _get_settings()
    auth_key = authenticate_request(request, settings["auth_keys"])  # 鉴权

    try:
        logging.info(
            f"OpenAI chat completion request: model={oa_req.model}, stream={oa_req.stream}"
        )
        gemini_payload = openai_request_to_gemini(oa_req)
    except Exception as e:
        logging.error(f"Error processing OpenAI request: {e}")
        return Response(
            content=json.dumps(
                {
                    "error": {
                        "message": f"Request processing failed: {e}",
                        "type": "invalid_request_error",
                        "code": 400,
                    }
                }
            ),
            status_code=400,
            media_type="application/json",
        )

    if oa_req.stream:

        async def openai_stream_generator():
            response_id = "chatcmpl-" + str(uuid.uuid4())
            try:
                # 注意：gemini_payload 现在直接包含了所有需要的信息
                response = api_client.send_gemini_request(
                    auth_key, {"model": oa_req.model, "request": gemini_payload}, is_streaming=True
                )
                if not isinstance(response, StreamingResponse):
                    # 如果不是流式响应，则尝试作为错误处理
                    error_content = (
                        response.body if hasattr(response, "body") else getattr(response, "content", b"")
                    )
                    try:
                        # 确保 error_content 是 bytes 类型
                        if isinstance(error_content, str):
                            error_data = {"error": {"message": error_content}}
                        elif isinstance(error_content, bytes):
                            error_data = {"error": {"message": error_content.decode("utf-8", "ignore")}}
                        else:
                            # 尝试转换为字符串
                            error_data = {"error": {"message": str(error_content)}}
                    except Exception:
                        error_data = {"error": {"message": "Unknown error"}}
                    yield f"data: {json.dumps(error_data)}\n\n"
                    yield "data: [DONE]\n\n"
                    return

                async for chunk in response.body_iterator:
                    # 确保 chunk 是 bytes 类型后再解码
                    if isinstance(chunk, bytes):
                        chunk_str = chunk.decode("utf-8", "ignore").strip()
                    elif hasattr(chunk, 'decode') and callable(getattr(chunk, 'decode')):
                        chunk_str = chunk.decode("utf-8", "ignore").strip() # type: ignore
                    else:
                        chunk_str = str(chunk).strip()
                    
                    if not chunk_str.startswith("data:"):
                        continue

                    chunk_data_str = chunk_str[len("data: ") :]
                    if not chunk_data_str or chunk_data_str == "[DONE]":
                        continue

                    try:
                        gemini_chunk = json.loads(chunk_data_str)
                        # 将 gemini 块转换为 openai 格式
                        openai_chunk = gemini_stream_chunk_to_openai(
                            gemini_chunk, oa_req.model, response_id
                        )
                        # 仅当转换后的块包含有效内容时才发送
                        if openai_chunk and openai_chunk.get("choices"):
                            yield f"data: {json.dumps(openai_chunk)}\n\n"
                    except json.JSONDecodeError:
                        logging.warning(
                            f"Failed to decode stream chunk as JSON: {chunk_data_str}"
                        )
                        continue

                # 确保流的末尾发送 [DONE]
                yield "data: [DONE]\n\n"

            except Exception as e:
                logging.error(f"Streaming failed: {e}")
                error_data = {
                    "error": {
                        "message": f"Streaming failed: {e}",
                        "type": "api_error",
                        "code": 500,
                    }
                }
                yield f"data: {json.dumps(error_data)}\n\n"
                yield "data: [DONE]\n\n"

        return StreamingResponse(
            openai_stream_generator(), media_type="text/event-stream"
        )

    else:  # 非流式
        try:
            # 注意：gemini_payload 现在直接包含了所有需要的信息
            response = api_client.send_gemini_request(
                auth_key, {"model": oa_req.model, "request": gemini_payload}, is_streaming=False
            )
            if not isinstance(response, Response) or response.status_code != 200:
                # client.py 中已处理错误，此处直接返回
                return response

            # client.py 中已处理用量，此处只需转换格式
            gemini_response_obj = json.loads(response.body)
            openai_response = gemini_response_to_openai(
                gemini_response_obj, oa_req.model
            )
            return openai_response
        except Exception as e:
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "message": f"Request failed: {e}",
                            "type": "api_error",
                            "code": 500,
                        }
                    }
                ),
                status_code=500,
                media_type="application/json",
            )


@router.get("/v1/models")
async def openai_list_models(request: Request):
    settings, _ = _get_settings()
    _ = authenticate_request(request, settings["auth_keys"])  # 鉴权
    from .config import SUPPORTED_MODELS

    openai_models = []
    for model in SUPPORTED_MODELS:
        model_id = model["name"].replace("models/", "")
        openai_models.append(
            {
                "id": model_id,
                "object": "model",
                "created": 1677610602,
                "owned_by": "google",
                "permission": [
                    {
                        "id": "modelperm-" + model_id.replace("/", "-"),
                        "object": "model_permission",
                        "created": 1677610602,
                        "allow_create_engine": False,
                        "allow_sampling": True,
                        "allow_logprobs": False,
                        "allow_search_indices": False,
                        "allow_view": True,
                        "allow_fine_tuning": False,
                        "organization": "*",
                        "group": None,
                        "is_blocking": False,
                    }
                ],
                "root": model_id,
                "parent": None,
            }
        )
    return {"object": "list", "data": openai_models}
