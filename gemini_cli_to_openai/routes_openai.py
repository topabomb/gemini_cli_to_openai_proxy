"""
OpenAI 兼容路由：从 src/openai_routes.py 迁移，保持行为不变。
"""
import json
import uuid
import asyncio
import logging
from fastapi import APIRouter, Request, Response, Depends
from fastapi.responses import StreamingResponse

from .transformers_openai import (
    openai_request_to_gemini,
    gemini_response_to_openai,
    gemini_stream_chunk_to_openai,
)
from .client import ApiClient, build_gemini_payload_from_openai
from .auth import authenticate_request


router = APIRouter()


def _get_settings():
    # 由 app.py 注入全局 settings
    from .state import settings, api_client
    return settings, api_client


@router.post("/v1/chat/completions")
async def openai_chat_completions(request: Request):
    settings, api_client = _get_settings()
    username = authenticate_request(request, settings["auth_password"])  # 鉴权

    try:
        body = await request.json()
        # 构造简单 pydantic-like 对象（避免引入新依赖）
        class _Msg:
            def __init__(self, d):
                self.role = d.get("role")
                self.content = d.get("content")
        class _Req:
            def __init__(self, d):
                self.model = d.get("model")
                self.messages = [_Msg(m) for m in d.get("messages", [])]
                self.stream = d.get("stream", False)
                self.temperature = d.get("temperature")
                self.top_p = d.get("top_p")
                self.max_tokens = d.get("max_tokens")
                self.stop = d.get("stop")
                self.frequency_penalty = d.get("frequency_penalty")
                self.presence_penalty = d.get("presence_penalty")
                self.n = d.get("n")
                self.seed = d.get("seed")
                self.response_format = d.get("response_format")

        oa_req = _Req(body)
        logging.info(f"OpenAI chat completion request: model={oa_req.model}, stream={oa_req.stream}")
        gemini_request_data = openai_request_to_gemini(oa_req)
        gemini_payload = build_gemini_payload_from_openai(gemini_request_data)
    except Exception as e:
        logging.error(f"Error processing OpenAI request: {e}")
        return Response(content=json.dumps({"error": {"message": f"Request processing failed: {e}", "type": "invalid_request_error", "code": 400}}), status_code=400, media_type="application/json")

    if oa_req.stream:
        async def openai_stream_generator():
            try:
                response = api_client.send_gemini_request(gemini_payload, is_streaming=True)
                if isinstance(response, StreamingResponse):
                    response_id = "chatcmpl-" + str(uuid.uuid4())
                    async for chunk in response.body_iterator:
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode("utf-8", "ignore")
                        if chunk.startswith("data: "):
                            try:
                                gemini_chunk = json.loads(chunk[6:])
                                if "error" in gemini_chunk:
                                    error_data = {"error": {"message": gemini_chunk["error"].get("message", "Unknown error"), "type": gemini_chunk["error"].get("type", "api_error"), "code": gemini_chunk["error"].get("code")}}
                                    yield f"data: {json.dumps(error_data)}\n\n"
                                    yield "data: [DONE]\n\n"
                                    return
                                openai_chunk = gemini_stream_chunk_to_openai(gemini_chunk, oa_req.model, response_id)
                                yield f"data: {json.dumps(openai_chunk)}\n\n"
                                await asyncio.sleep(0)
                            except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
                                continue
                    yield "data: [DONE]\n\n"
                else:
                    error_msg = "Streaming request failed"
                    status_code = getattr(response, "status_code", 500)
                    if hasattr(response, "body"):
                        try:
                            error_body = response.body
                            if isinstance(error_body, bytes):
                                error_body = error_body.decode("utf-8", "ignore")
                            error_data = json.loads(error_body)
                            if "error" in error_data:
                                error_msg = error_data["error"].get("message", error_msg)
                        except Exception:
                            pass
                    error_data = {"error": {"message": error_msg, "type": "invalid_request_error" if status_code == 404 else "api_error", "code": status_code}}
                    yield f"data: {json.dumps(error_data)}\n\n"
                    yield "data: [DONE]\n\n"
            except Exception as e:
                error_data = {"error": {"message": f"Streaming failed: {e}", "type": "api_error", "code": 500}}
                yield f"data: {json.dumps(error_data)}\n\n"
                yield "data: [DONE]\n\n"

        return StreamingResponse(openai_stream_generator(), media_type="text/event-stream")

    else:
        try:
            response = api_client.send_gemini_request(gemini_payload, is_streaming=False)
            if isinstance(response, Response) and response.status_code != 200:
                try:
                    error_body = response.body
                    if isinstance(error_body, bytes):
                        error_body = error_body.decode("utf-8", "ignore")
                    error_data = json.loads(error_body)
                    if "error" in error_data:
                        openai_error = {"error": {"message": error_data["error"].get("message", f"API error: {response.status_code}"), "type": error_data["error"].get("type", "invalid_request_error" if response.status_code == 404 else "api_error"), "code": error_data["error"].get("code", response.status_code)}}
                        return Response(content=json.dumps(openai_error), status_code=response.status_code, media_type="application/json")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
                return Response(content=json.dumps({"error": {"message": f"API error: {response.status_code}", "type": "invalid_request_error" if response.status_code == 404 else "api_error", "code": response.status_code}}), status_code=response.status_code, media_type="application/json")

            try:
                gemini_response = json.loads(response.body)
                openai_response = gemini_response_to_openai(gemini_response, oa_req.model)
                return openai_response
            except (json.JSONDecodeError, AttributeError) as e:
                return Response(content=json.dumps({"error": {"message": f"Failed to process response: {e}", "type": "api_error", "code": 500}}), status_code=500, media_type="application/json")
        except Exception as e:
            return Response(content=json.dumps({"error": {"message": f"Request failed: {e}", "type": "api_error", "code": 500}}), status_code=500, media_type="application/json")


@router.get("/v1/models")
async def openai_list_models(request: Request):
    settings, _ = _get_settings()
    _ = authenticate_request(request, settings["auth_password"])  # 鉴权
    from .config import SUPPORTED_MODELS
    openai_models = []
    for model in SUPPORTED_MODELS:
        model_id = model["name"].replace("models/", "")
        openai_models.append({
            "id": model_id,
            "object": "model",
            "created": 1677610602,
            "owned_by": "google",
            "permission": [{
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
            }],
            "root": model_id,
            "parent": None,
        })
    return {"object": "list", "data": openai_models}


