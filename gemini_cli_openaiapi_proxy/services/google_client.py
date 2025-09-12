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
from typing import Dict, Any, AsyncGenerator, Tuple

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
from datetime import datetime, timezone,timedelta

logger = logging.getLogger(__name__)
def random_date(start_year=2000, end_year=2025):
    """生成随机日期字符串 YYYY-MM-DD"""
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 12, 31)
    delta = end - start
    random_days = random.randint(0, delta.days)
    return (start + timedelta(days=random_days)).strftime("%Y-%m-%d")
greetings_multilang = [
    "早上好",       # 中文 - Good morning
    "谢谢",         # 中文 - Thank you
    "再见",         # 中文 - Goodbye
    "Hello",        # 英文 - Hello
    "Goodbye",      # 英文 - Goodbye
    "Bonjour",      # 法语 - Hello / Good morning
    "Gracias",      # 西班牙语 - Thank you
    "Ciao",         # 意大利语 - Hello / Goodbye
    "Guten Tag",    # 德语 - Good day
    "こんにちは"     # 日语 - Hello / Good afternoon
]
# 用于健康检查的简单对话列表
HEALTH_CHECK_PROMPTS = [
    {"contents": [{"role": "user", "parts": [{"text": f"查询纽约{random_date()}的气温"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"计算{random.randint(1000, 999999)}的平方根，提供结果"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"列出{random.randint(2,5)}个随机的英文单词"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"把'{random.choice(['Python','Rust','TypeScript','Vue'])}'倒序输出"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"生成一个1到{random.randint(50,200)}之间的随机数"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"火星在大气温度{random.randint(-150, 30)}摄氏度时的地面温度大约是多少"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"把{random_date()}加上{random.randint(1, 365)}天后输出"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"给我一个{random.randint(4,6)}个字的中文成语"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"输出一个{random.randint(1,4)}句的唐诗"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"列出{random.randint(2,5)}个质数"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"翻译'{random.choice(greetings_multilang)}'成英文"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"提供一个{random.randint(1,4)}位的四则运算题目"}]}]},
    {"contents": [{"role": "user", "parts": [{"text": f"提供一个{random.randint(10,40)}单词的英文例句"}]}]},
]

class GoogleApiClient:

    async def check_simple_model_call(self, credential: ManagedCredential) -> Tuple[bool, str]:
        """
        原子健康检查：尝试一次极简的模型调用，精确模拟真实请求。
        """
        if not credential.project_id:
            return False, "Health check skipped due to missing project_id."
            
        gemini_request = random.choice(HEALTH_CHECK_PROMPTS)
        model_name = "gemini-2.5-flash-lite" # 使用稳定基础模型
        
        sent_text = gemini_request["contents"][0]["parts"][0]["text"]
        logger.debug(f"Performing '{self.check_simple_model_call.__name__}' for {credential.log_safe_id} with prompt: '{sent_text}'")

        try:
            # 直接调用内部的 _prepare_request_components 来确保 URL 和 payload 100% 一致
            post_data, target_url, headers, timeout_config = self._prepare_request_components(
                managed_cred=credential,
                model=model_name,
                gemini_request=gemini_request,
                is_streaming=False
            )
            
            resp = await self.http_client.post(
                target_url, content=post_data, headers=headers, timeout=timeout_config
            )
            resp.raise_for_status()
            
            # 解析响应以获取生成的内容
            response_data = resp.json()
            try:
                # 尝试从标准路径提取文本
                generated_text = response_data['response']['candidates'][0]['content']['parts'][0]['text']
                message = f"Successfully generated content: ask(${sent_text}),answer '{generated_text.strip()}'"
            except (KeyError, IndexError, TypeError):
                print("Failed to parse response data:", json.dumps(response_data))
                # 如果结构不符合预期，则使用通用成功消息
                message = "Successfully generated content (but failed to parse response)."

            logger.info(f"Health check '{self.check_simple_model_call.__name__}' successful for {credential.log_safe_id}: {message}")
            return True, message
        except Exception as e:
            message = f"Health check '{self.check_simple_model_call.__name__}' failed. Error: {e}"
            logger.warning(f"For credential '{credential.log_safe_id}': {message}")
            return False, message
    async def _check_token_counter(self, credential: ManagedCredential) -> Tuple[bool, str]:
        """
        原子健康检查：通过使用countTokens API来验证凭据在项目上下文中的执行权限。
        """
        check_name = "token_counter"
        url = f"{CODE_ASSIST_ENDPOINT}/v1internal:countTokens"
        gemini_request = random.choice(HEALTH_CHECK_PROMPTS)
        payload = {
            "request": {
            "model": "models/gemini-2.5-flash-lite",
            "contents": gemini_request["contents"][0] #[{"parts": [{"text": "health check"}]}]
            }
        }
        
        try:
            response = await self.http_client.post(
                url,
                headers={"Authorization": f"Bearer {credential.credentials.token}", "Content-Type": "application/json"},
                json=payload,
                timeout=10
            )
            if response.status_code == 200:
                response_data = response.json()
                message = f"Successfully counted tokens.{response_data.get('totalTokens','No message returned.')}"
                logger.debug(f"Health check '{check_name}' passed for {credential.log_safe_id}: {message}")
                return True, message
            else:
                message = f"Failed to count tokens. Status: {response.status_code}, Response: {response.text}"
                logger.warning(f"Health check '{check_name}' failed for {credential.log_safe_id}: {message}")
                return False, message
        except Exception as e:
            message = f"Exception in '{check_name}' for {credential.log_safe_id}. Error: {e}"
            logger.error(message, exc_info=True)
            return False, message

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
                if e.response.status_code in [400, 404]:
                    log_msg += " This is a non-retriable client error."
                    logger.warning(log_msg)
                    # 请求级错误，不惩罚凭据，不重试，直接透传错误
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    error_text = await e.response.aread()
                    return self._create_error_response(f"API request failed: {error_text.decode(errors='ignore')}", e.response.status_code, is_streaming=False)

                elif e.response.status_code == 401 and attempt < max_retries - 1:
                    log_msg += " Marking credential as EXPIRED and retrying."
                    logger.warning(log_msg)
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    managed_cred.mark_expired()
                    continue

                elif e.response.status_code == 429 and attempt < max_retries - 1:
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
                    # 如果状态码不是 200，则在流关闭前读取错误内容，然后抛出异常
                    if resp.status_code != 200:
                        error_body = await resp.aread()
                        # 将错误内容附加到 response 对象上，以便 except 块可以访问
                        setattr(resp, "error_body", error_body)
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
                if e.response.status_code in [400, 404]:
                    log_msg += " This is a non-retriable client error."
                    logger.warning(log_msg)
                    # 请求级错误，不惩罚凭据，不重试，直接透传错误
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    # 从我们之前附加的属性中安全地获取错误内容
                    error_text = getattr(e.response, 'error_body', b'')
                    yield self._create_error_sse_chunk(f"API request failed with status {e.response.status_code}:{error_text.decode(errors='ignore')}", e.response.status_code)
                    return

                elif e.response.status_code == 401 and attempt < max_retries - 1:
                    log_msg += " Marking credential as EXPIRED and retrying."
                    logger.warning(log_msg)
                    await self.usage_tracker.record_failed_request(auth_key, managed_cred.id, model, reason=failure_reason)
                    managed_cred.mark_expired()
                    continue

                elif e.response.status_code == 429 and attempt < max_retries - 1:
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
