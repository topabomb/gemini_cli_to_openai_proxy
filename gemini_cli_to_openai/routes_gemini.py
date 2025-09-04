"""
原生 Gemini 路由：从 src/gemini_routes.py 迁移，保持行为不变。
"""
import json
import logging
from fastapi import APIRouter, Request, Response

from .client import ApiClient, build_gemini_payload_from_native
from .auth import authenticate_request
from .config import SUPPORTED_MODELS


router = APIRouter()


def _get_settings():
    from .state import settings, api_client
    return settings, api_client


@router.get("/v1beta/models")
async def gemini_list_models(request: Request):
    settings, _ = _get_settings()
    _ = authenticate_request(request, settings["auth_password"])  # 鉴权
    models_response = {"models": SUPPORTED_MODELS}
    return Response(content=json.dumps(models_response), status_code=200, media_type="application/json; charset=utf-8")


@router.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gemini_proxy(request: Request, full_path: str):
    settings, api_client = _get_settings()
    _ = authenticate_request(request, settings["auth_password"])  # 鉴权
    try:
        post_data = await request.body()
        is_streaming = "stream" in full_path.lower()
        model_name = _extract_model_from_path(full_path)
        if not model_name:
            return Response(content=json.dumps({"error": {"message": f"Could not extract model name from path: {full_path}", "code": 400}}), status_code=400, media_type="application/json")
        incoming_request = json.loads(post_data) if post_data else {}
        gemini_payload = build_gemini_payload_from_native(incoming_request, model_name)
        response = api_client.send_gemini_request(gemini_payload, is_streaming=is_streaming)
        return response
    except Exception as e:
        return Response(content=json.dumps({"error": {"message": f"Proxy error: {e}", "code": 500}}), status_code=500, media_type="application/json")


def _extract_model_from_path(path: str) -> str:
    parts = path.split('/')
    try:
        idx = parts.index('models')
        if idx + 1 < len(parts):
            model_name = parts[idx + 1]
            if ':' in model_name:
                model_name = model_name.split(':')[0]
            return model_name
    except ValueError:
        pass
    return None


@router.get("/v1/models")
async def gemini_list_models_v1(request: Request):
    return await gemini_list_models(request)


