"""
原生 Gemini API 路由模块。
"""

import json
import logging
from typing import Optional
from fastapi import APIRouter, Request, Response, Depends

from ...services.google_client import GoogleApiClient
from ...utils.transformers import build_gemini_payload_from_native
from ..security import get_api_key
from ..dependencies import get_google_api_client

router = APIRouter(
    prefix="/v1beta",
    tags=["Gemini Native"],
)

from ...core.models import SUPPORTED_MODELS

@router.get("/models")
async def list_models(
    request: Request,
    api_key: str = Depends(get_api_key)
):
    """返回支持的 Gemini 模型列表。"""
    return {"models": SUPPORTED_MODELS}

@router.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_gemini_requests(
    request: Request,
    full_path: str,
    api_key: str = Depends(get_api_key),
    client: GoogleApiClient = Depends(get_google_api_client)
):
    """一个通用的代理端点，用于转发所有 Gemini API 请求。"""
    try:
        # 提取模型名称
        parts = full_path.split("/")
        model_name = None
        if "models" in parts:
            model_idx = parts.index("models")
            if model_idx + 1 < len(parts):
                model_name = parts[model_idx + 1].split(":")[0]

        if not model_name:
            return Response(content=json.dumps({"error": "Could not extract model name from path"}), status_code=400)

        # 读取请求体并构建 payload
        body = await request.body()
        incoming_request = json.loads(body) if body else {}
        gemini_payload = build_gemini_payload_from_native(incoming_request, model_name)
        
        is_streaming = "stream" in full_path.lower()
        # 兼容模式：当 compat=openai / true / 1 / oai 时，输出 OpenAI 风格 SSE
        compat_q = request.query_params.get("compat") or request.query_params.get("openai_compat")
        compat_openai = str(compat_q).lower() in ["openai", "true", "1", "yes", "oai"]

        return await client.send_gemini_request(
            auth_key=api_key,
            model=gemini_payload["model"],
            gemini_request=gemini_payload["request"],
            is_streaming=is_streaming,
            compat_openai=compat_openai
        )
    except Exception as e:
        logging.error(f"Gemini proxy error: {e}", exc_info=True)
        return Response(content=json.dumps({"error": f"Proxy error: {e}"}), status_code=500)
