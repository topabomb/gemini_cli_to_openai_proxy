"""
OpenAI 兼容 API 路由模块。
"""

import json
import logging
import time

logger = logging.getLogger(__name__)
import uuid
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse

from ...services.google_client import GoogleApiClient
from ...utils.transformers import openai_to_gemini_request
from ..dependencies import get_google_api_client
from ..security import get_api_key
from ...core.models import SUPPORTED_MODELS

router = APIRouter(
    prefix="/v1",
    tags=["OpenAI Compatible"],
)

@router.get("/models")
async def list_models(api_key: str = Depends(get_api_key)):
    """返回一个符合 OpenAI 格式的模型列表。"""
    models_data = []
    for model in SUPPORTED_MODELS:
        model_id = model["name"].replace("models/", "")
        models_data.append({
            "id": model_id,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "google",
        })
    return {"object": "list", "data": models_data}

@router.get("/models/{model_id:path}")
async def retrieve_model(model_id: str, api_key: str = Depends(get_api_key)):
    """返回单个模型的详细信息。"""
    full_model_name = f"models/{model_id}"
    for model in SUPPORTED_MODELS:
        if model["name"] == full_model_name:
            return {
                "id": model_id,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "google",
            }
    raise HTTPException(status_code=404, detail="Model not found")

@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    api_key: str = Depends(get_api_key),
    client: GoogleApiClient = Depends(get_google_api_client)
):
    """处理聊天补全请求。"""
    try:
        openai_request = await request.json()
        is_streaming = openai_request.get("stream", False)

        gemini_payload = await openai_to_gemini_request(openai_request)

        return await client.send_gemini_request(
            auth_key=api_key,
            model=gemini_payload["model"],
            gemini_request=gemini_payload["request"],
            is_streaming=is_streaming,
            compat_openai=True
        )
    except ValueError as e:
        logger.error(f"OpenAI compatible API error: {e}", exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"error": {"message": str(e), "type": "invalid_request_error"}}
        )
    except Exception as e:
        logger.error(f"OpenAI compatible API error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": {"message": f"Internal Server Error: {e}", "type": "server_error"}}
        )
