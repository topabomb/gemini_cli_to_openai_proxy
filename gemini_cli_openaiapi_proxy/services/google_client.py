"""
Google API 异步客户端服务模块：
- 使用 httpx.AsyncClient 实现全异步请求。
- 统一从 CredentialManager 获取凭据。
- 处理非流式与流式（SSE）转发逻辑、超时、429/403 重试与轮转策略。
- 解析响应并记录用量统计。
"""
import json
import logging
import asyncio
import time
import uuid
import random
from typing import Dict, Any, AsyncGenerator

import httpx
from fastapi import Response
from fastapi.responses import StreamingResponse, JSONResponse

from ..core.config import SettingsDict, CODE_ASSIST_ENDPOINT
from .credential_manager import CredentialManager
from ..core.types import ManagedCredential
from .usage_tracker import UsageTracker
from ..core.models import get_base_model_name
from ..utils.sanitizer import sanitize_email
from ..utils.transformers import gemini_to_openai_response, gemini_to_openai_stream_chunk
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# 用于健康检查的简单对话列表
HEALTH_CHECK_PROMPTS = [
    {"contents": [{"role": "user", "parts": [{"text": "Hi, are you there?"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": "Hello, can you hear me?"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": "What is the capital of France?"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": "Please say 'test'."}]}]},
]

class GoogleApiClient:
    async def check_model_list_access(self, credential: ManagedCredential) -> bool:
        """
        原子健康检查：尝试获取模型列表。
        这是一个轻量级的检查，用于验证凭据的基本 API 访问权限。
        """
        try:
            # 根据官方文档，v1beta/models 是一个有效的端点
            resp = await self.http_client.get(
                f"{CODE_ASSIST_ENDPOINT}/v1beta/models?pageSize=10",
                headers={"Authorization": f"Bearer {credential.credentials.token}"},
                timeout=5
            )
            resp.raise_for_status()
            logger.debug(f"Health check 'model_list' successful for {credential.log_safe_id}.")
            return True
        except Exception as e:
            logger.warning(
                f"Health check 'model_list' failed for credential "
                f"'{credential.log_safe_id}'. Error: {e}"
            )
            return False

    async def check_userinfo_access(self, credential: ManagedCredential) -> bool:
        """
        原子健康检查：尝试获取用户信息。
        此检查验证 OAuth token 是否对标准 Google 用户信息端点有效。
        """
        try:
            # 这是标准的 OpenID Connect 用户信息端点
            resp = await self.http_client.get(
                "https://openidconnect.googleapis.com/v1/userinfo",
                headers={"Authorization": f"Bearer {credential.credentials.token}"},
                timeout=5
            )
            resp.raise_for_status()
            logger.debug(f"Health check 'userinfo' successful for {credential.log_safe_id}.")
            return True
        except Exception as e:
            logger.warning(
                f"Health check 'userinfo' failed for credential "
                f"'{credential.log_safe_id}'. Error: {e}"
            )
            return False

    async def check_simple_model_call(self, credential: ManagedCredential) -> bool:
        """
        原子健康检查：尝试一次极简的模型调用。
        这是最真实的检查，因为它模拟了实际的 generateContent 调用。
        """
        if not credential.project_id:
            logger.warning(f"Health check 'simple_model_call' skipped for {credential.log_safe_id} due to missing project_id.")
            return False
            
        # 从列表中随机选择一个 payload
        payload = random.choice(HEALTH_CHECK_PROMPTS)
        model_name = "gemini-2.5-flash-lite"
        
        # 记录将要发送的内容
        sent_text = payload["contents"][0]["parts"][0]["text"]
        logger.debug(f"Performing 'simple_model_call' health check for {credential.log_safe_id} with prompt: '{sent_text}'")

        try:
            # 端点和 payload 结构遵循 v1beta generateContent API 规范
            url = f"{CODE_ASSIST_ENDPOINT}/v1beta/models/{model_name}:generateContent"
            full_payload = {"request": payload, "project": credential.project_id, "model": model_name}
            
            resp = await self.http_client.post(
                url, json=full_payload,
                headers={"Authorization": f"Bearer {credential.credentials.token}"},
                timeout=20
            )
            resp.raise_for_status()
            logger.info(f"Health check 'simple_model_call' successful for {credential.log_safe_id}.")
            return True
        except Exception as e:
            logger.warning(
                f"Health check 'simple_model_call' failed for credential "
                f"'{credential.log_safe_id}'. Error: {e}"
            )
            return False
    """
    一个全异步的 Google API 客户端。
    """

    def __init__(self, settings: SettingsDict, cred_manager: CredentialManager, http_client: httpx.AsyncClient, usage_tracker: UsageTracker):
        self.settings = settings
        self.cred_manager = cred_manager
        self.http_client = http_client
        self.usage_tracker = usage_tracker

    async def send_gemini_request(self, auth_key: str, model: str, gemini_request: Dict[str, Any], is_streaming: bool, compat_openai: bool = False) -> Response:
        """
        异步发送请求到 Google Gemini API，并处理重试和凭据轮转。
        """
        if is_streaming:
            # 对于流式请求，返回一个包含完整重试逻辑的 StreamingResponse
            return StreamingResponse(
                self._streaming_request_with_retries(auth_key, model, gemini_request, compat_openai),
                media_type="text/event-stream; charset=utf-8",
                headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
            )
        else:
            # 对于非流式请求，使用现有的 try-except-retry 模式
            return await self._non_streaming_request_with_retries(auth_key, model, gemini_request, compat_openai)

    async def _non_streaming_request_with_retries(self, auth_key: str, model: str, gemini_request: Dict[str, Any], compat_openai: bool) -> Response:
        """处理非流式请求的重试逻辑。"""
        max_retries = 3
        last_error = None
        
        for attempt in range(max_retries):
            managed_cred = await self.cred_manager.get_available()
            if not managed_cred:
                logger.error("[ApiClient] No valid credentials available for non-streaming request.")
                return self._create_error_response("No valid credentials available.", 500, is_streaming=False)

            # --- 注入请求策略检查 ---
            is_allowed, reason = await self.usage_tracker.check_request_allowed(
                auth_key=auth_key,
                cred_id=managed_cred.id,
                model_name=model
            )
            if not is_allowed:
                log_msg = f"[ApiClient] Request denied by policy for {auth_key}/{managed_cred.id}/{model}. Reason: {reason}"
                logger.warning(log_msg)
                await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, f"Denied: {reason}")
                return self._create_error_response(f"Request denied by policy: {reason}", 403, is_streaming=False)
            # --- 注入结束 ---

            cred_id_for_log = f"{managed_cred.id}({sanitize_email(managed_cred.email)})"
            logger.info(f"[ApiClient] Attempt {attempt + 1}/{max_retries} (Non-Streaming): Sending request with {cred_id_for_log}")

            try:
                # 构造请求
                post_data, target_url, headers, timeout_config = self._prepare_request_components(managed_cred, model, gemini_request, is_streaming=False)
                
                # 发送请求
                resp = await self.http_client.post(target_url, content=post_data, headers=headers, timeout=timeout_config)
                resp.raise_for_status()

                # 处理成功响应
                response_data = await resp.aread()
                try:
                    json_data = json.loads(response_data)
                    response_obj = json_data.get("response", {})
                    usage_metadata = response_obj.get("usageMetadata")
                    await self.usage_tracker.record_successful_request(auth_key, managed_cred.id, model, usage_metadata or {})
                    
                    if compat_openai:
                        openai_response = gemini_to_openai_response(json_data, model)
                        return JSONResponse(content=openai_response, status_code=200)
                except json.JSONDecodeError:
                    logger.warning("[ApiClient] Failed to parse non-stream response for usage tracking.")
                    await self.usage_tracker.record_successful_request(auth_key, managed_cred.id, model, {})

                return Response(content=response_data, status_code=resp.status_code, media_type=resp.headers.get("Content-Type"))

            except httpx.HTTPStatusError as e:
                last_error = e
                log_msg = f"[ApiClient] Request failed with status {e.response.status_code} for {cred_id_for_log}."
                failure_reason = str(e.response.status_code)

                if e.response.status_code == 429 and attempt < max_retries - 1:
                    log_msg += " Marking credential as RATE_LIMITED and retrying."
                    logger.warning(log_msg)
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    managed_cred.mark_rate_limited()
                    continue
                elif e.response.status_code == 403 and attempt < max_retries - 1:
                    log_msg += f" Marking credential as PERMISSION_DENIED and retrying."
                    logger.warning(log_msg)
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    managed_cred.mark_permission_denied()
                    continue
                else:
                    log_msg += " Max retries reached or error is not recoverable."
                    logger.error(log_msg)
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    managed_cred.mark_as_permanent_error(f"HTTP {e.response.status_code}")
                    error_text = await e.response.aread()
                    return self._create_error_response(f"API request failed: {error_text.decode(errors='ignore')}", e.response.status_code, is_streaming=False)
            
            except Exception as e:
                last_error = e
                logger.error(f"[ApiClient] An unexpected error occurred: {e}. Credential: {cred_id_for_log}", exc_info=True)
                await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason="Exception")
                return self._create_error_response(f"An unexpected error occurred: {e}", 500, is_streaming=False)
        
        logger.error(f"[ApiClient] All retries failed for non-streaming request. Last error: {last_error}")
        return self._create_error_response("Request failed after all retries.", 500, is_streaming=False)

    async def _streaming_request_with_retries(self, auth_key: str, model: str, gemini_request: Dict[str, Any], compat_openai: bool) -> AsyncGenerator[bytes, None]:
        """
        一个包含完整重试逻辑的异步生成器，用于处理流式请求。
        """
        max_retries = 3
        last_error = None
        response_id = f"chatcmpl-{uuid.uuid4()}"
        is_first_chunk = True

        for attempt in range(max_retries):
            managed_cred = await self.cred_manager.get_available()
            if not managed_cred:
                logger.error("[ApiClient] No valid credentials available for streaming request.")
                yield self._create_error_sse_chunk("No valid credentials available.", 500)
                return

            # --- 注入请求策略检查 ---
            is_allowed, reason = await self.usage_tracker.check_request_allowed(
                auth_key=auth_key,
                cred_id=managed_cred.id,
                model_name=model
            )
            if not is_allowed:
                log_msg = f"[ApiClient] Request denied by policy for {auth_key}/{managed_cred.id}/{model}. Reason: {reason}"
                logger.warning(log_msg)
                await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, f"Denied: {reason}")
                yield self._create_error_sse_chunk(f"Request denied by policy: {reason}", 403)
                return
            # --- 注入结束 ---

            cred_id_for_log = f"{managed_cred.id}({sanitize_email(managed_cred.email)})"
            logger.info(f"[ApiClient] Attempt {attempt + 1}/{max_retries} (Streaming): Sending request with {cred_id_for_log}")

            try:
                post_data, target_url, headers, timeout_config = self._prepare_request_components(managed_cred, model, gemini_request, is_streaming=True)
                
                usage_metadata: Dict[str, Any] = {}
                async with self.http_client.stream("POST", target_url, content=post_data, headers=headers, timeout=timeout_config) as resp:
                    # 如果状态码不是 200，则直接进入异常处理逻辑，以便重试
                    if resp.status_code != 200:
                        resp.raise_for_status()

                    # --- 核心流式转发逻辑 ---
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        if line.startswith("data: "):
                            chunk_data = line[len("data: "):]
                            try:
                                obj = json.loads(chunk_data)
                                logger.debug(f"[ApiClient] Stream chunk received: {obj}")
                                response_obj = obj.get("response", {})
                                if "usageMetadata" in response_obj and "totalTokenCount" in response_obj["usageMetadata"]:
                                    usage_metadata = response_obj["usageMetadata"]
                                
                                if compat_openai:
                                    openai_chunk = gemini_to_openai_stream_chunk(obj, model, response_id, is_first_chunk)
                                    yield f"data: {json.dumps(openai_chunk, ensure_ascii=False)}\n\n".encode("utf-8")
                                    if is_first_chunk:
                                        is_first_chunk = False
                                else:
                                    yield f"data: {json.dumps(response_obj or obj, separators=(',', ':'))}\n\n".encode("utf-8")
                            except json.JSONDecodeError:
                                logger.warning(f"[ApiClient] Failed to decode stream chunk as JSON: {chunk_data}")
                                yield (line + "\n").encode("utf-8")
                        else:
                            yield (line + "\n").encode("utf-8")
                    # --- 核心流式转发逻辑结束 ---

                # 流成功结束
                if compat_openai:
                    yield b"data: [DONE]\n\n"
                await self.usage_tracker.record_successful_request(auth_key, managed_cred.id, model, usage_metadata)
                return # 成功，退出生成器

            except httpx.HTTPStatusError as e:
                last_error = e
                log_msg = f"[ApiClient] Request failed with status {e.response.status_code} for {cred_id_for_log}."
                failure_reason = str(e.response.status_code)

                if e.response.status_code == 429 and attempt < max_retries - 1:
                    log_msg += " Marking credential as RATE_LIMITED and retrying."
                    logger.warning(log_msg)
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    managed_cred.mark_rate_limited()
                    continue  # 进行下一次重试
                elif e.response.status_code == 403 and attempt < max_retries - 1:
                    log_msg += f" Marking credential as PERMISSION_DENIED and retrying."
                    logger.warning(log_msg)
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    managed_cred.mark_permission_denied()
                    continue # 进行下一次重试
                else:
                    log_msg += " Max retries reached or error is not recoverable."
                    logger.error(log_msg)
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    managed_cred.mark_as_permanent_error(f"HTTP {e.response.status_code}")
                    yield self._create_error_sse_chunk(f"API request failed with status {e.response.status_code}", e.response.status_code)
                    return
            
            except Exception as e:
                last_error = e
                logger.error(f"[ApiClient] An unexpected error occurred during stream: {e}. Credential: {cred_id_for_log}", exc_info=True)
                await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason="Exception")
                yield self._create_error_sse_chunk(f"An unexpected error occurred: {e}", 500)
                return

        logger.error(f"[ApiClient] All retries failed for streaming request. Last error: {last_error}")
        yield self._create_error_sse_chunk("Request failed after all retries.", 500)

    def _prepare_request_components(self, managed_cred: ManagedCredential, model: str, gemini_request: Dict[str, Any], is_streaming: bool) -> tuple:
        """准备请求所需的各种组件。"""
        creds = managed_cred.credentials
        headers = {"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"}
        
        final_payload = {"model": get_base_model_name(model), "project": managed_cred.project_id, "request": gemini_request}
        post_data = json.dumps(final_payload)
        
        action = "streamGenerateContent" if is_streaming else "generateContent"
        target_url = f"{CODE_ASSIST_ENDPOINT}/v1internal:{action}"
        if is_streaming:
            target_url += "?alt=sse"
            
        timeouts = self.settings["request_timeouts"]
        timeout_config = httpx.Timeout(
            connect=timeouts.get("connect"),
            read=timeouts.get("read"),
            write=timeouts.get("write"),
            pool=timeouts.get("pool"),
        )
        
        logger.debug(f"[ApiClient] Sending request to {target_url} with body: {post_data}")
        return post_data, target_url, headers, timeout_config

    def _create_error_response(self, message: str, status_code: int, is_streaming: bool) -> Response:
        """为非流式请求创建统一的错误响应。"""
        error_content = {"error": {"message": message, "code": status_code}}
        return Response(content=json.dumps(error_content), status_code=status_code, media_type="application/json")

    def _create_error_sse_chunk(self, message: str, status_code: int) -> bytes:
        """为流式请求创建格式化的 SSE 错误块。"""
        error_content = {"error": {"message": message, "code": status_code}}
        return f"data: {json.dumps(error_content)}\n\n".encode("utf-8")
