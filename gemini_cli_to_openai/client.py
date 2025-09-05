"""
Google API 客户端模块：
- 统一从 CredentialManager 获取凭据。
- 处理非流式与流式（SSE）转发逻辑、超时、429/403 重试与轮转策略。
- 解析响应并记录用量统计。
"""
import json
import logging
import asyncio
import time
from typing import Dict, Any, cast

import requests
from fastapi import HTTPException, Response
from fastapi.responses import StreamingResponse

from .config import (
    CODE_ASSIST_ENDPOINT,
    DEFAULT_SAFETY_SETTINGS,
    get_base_model_name,
    is_search_model,
    get_thinking_budget,
    should_include_thoughts,
)
from .utils import get_user_agent
from .credentials import CredentialManager
from .config import SettingsDict


class ApiClient:
    """
    Google API 客户端，负责发送请求到 Google 的 Gemini API 并处理响应。

    此类会从 CredentialManager 获取有效的凭据，处理请求的发送、重试、轮转，
    并根据响应类型（流式或非流式）进行相应的处理，同时记录用量统计。
    """

    def __init__(self, cred_manager: CredentialManager, settings: SettingsDict):
        """
        初始化 ApiClient 实例。

        Args:
            cred_manager (CredentialManager): 凭据管理器实例，用于获取和管理 API 凭据。
            settings (SettingsDict): 应用配置字典，包含超时等设置。
        """
        self.credential_manager = cred_manager
        self.settings = settings

    def send_gemini_request(
        self, auth_key: str, payload: Dict, is_streaming: bool = False
    ) -> Response:
        """
        发送请求到 Google Gemini API。

        此方法会处理凭据获取、请求发送、错误处理（如 429、403）、重试和轮转逻辑。
        根据 `is_streaming` 参数，它会调用不同的响应处理方法。

        Args:
            auth_key (str): 用于标识请求来源的认证密钥。
            payload (Dict): 包含模型名称和请求数据的字典。
            is_streaming (bool): 是否为流式请求。

        Returns:
            Response: FastAPI 的 Response 对象，包含 API 的响应数据或错误信息。
        """
        model = payload.get("model")
        if not isinstance(model, str):
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "message": "Request payload must include a 'model' field as a string.",
                            "code": 400,
                        }
                    }
                ),
                status_code=400,
                media_type="application/json",
            )

        logging.debug(f"Preparing request: model={model}, streaming={is_streaming}")
        managed = self.credential_manager.get_available()
        if not managed:
            logging.error("No valid credentials available")
            if is_streaming:
                return self._sse_error("No valid credentials available.", 500)
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "message": "No valid credentials available.",
                            "code": 500,
                        }
                    }
                ),
                status_code=500,
                media_type="application/json",
            )

        creds = managed.credentials
        proj_id = managed.project_id
        cred_id = managed.id
        logging.debug(
            f"Using credential: id={cred_id}, email={getattr(managed, 'email', None)}, project={proj_id}"
        )

        # 检查请求是否被允许
        from .state import usage_tracker

        if usage_tracker:
            base_model_name = get_base_model_name(model)
            allowed, reason = usage_tracker.check_request_allowed(
                auth_key, cred_id, model, base_model_name
            )
            if not allowed:
                logging.warning(
                    f"Request denied for auth_key={auth_key}, model={model}. Reason: {reason}"
                )
                raise HTTPException(status_code=429, detail=f"Request denied: {reason}")

        if getattr(creds, "expiry", None) is not None:
            # 统一比较使用 naive UTC
            try:
                from datetime import timezone

                if creds.expiry.tzinfo is not None:
                    exp_naive = creds.expiry.astimezone(timezone.utc).replace(
                        tzinfo=None
                    )
                else:
                    exp_naive = creds.expiry
                from datetime import datetime

                now_naive = datetime.utcnow()
                if exp_naive:
                    expired_flag = exp_naive <= now_naive
                else:
                    expired_flag = creds.expired
            except Exception:
                expired_flag = creds.expired
        else:
            expired_flag = creds.expired

        if expired_flag and creds.refresh_token:
            try:
                if not self.credential_manager._refresh_credential(managed):
                    managed = self.credential_manager.get_available()
                    if not managed:
                        logging.error("No valid credentials after refresh")
                        if is_streaming:
                            return self._sse_error(
                                "No valid credentials after refresh.", 500
                            )
                        return Response(
                            content=json.dumps(
                                {
                                    "error": {
                                        "message": "No valid credentials after refresh.",
                                        "code": 500,
                                    }
                                }
                            ),
                            status_code=500,
                            media_type="application/json",
                        )
                    creds = managed.credentials
                    proj_id = managed.project_id
                    cred_id = managed.id
            except Exception as e:
                logging.error(f"Token refresh failed for {cred_id}: {e}")
                managed = self.credential_manager.get_available()
                if not managed:
                    if is_streaming:
                        return self._sse_error("Token refresh failed.", 500)
                    return Response(
                        content=json.dumps(
                            {"error": {"message": "Token refresh failed.", "code": 500}}
                        ),
                        status_code=500,
                        media_type="application/json",
                    )
                creds = managed.credentials
                proj_id = managed.project_id
                cred_id = managed.id

        if not creds.token:
            managed = self.credential_manager.get_available()
            if not managed:
                logging.error("No access token")
                if is_streaming:
                    return self._sse_error("No access token.", 500)
                return Response(
                    content=json.dumps(
                        {"error": {"message": "No access token.", "code": 500}}
                    ),
                    status_code=500,
                    media_type="application/json",
                )
            creds = managed.credentials
            proj_id = managed.project_id
            cred_id = managed.id

        final_payload = {
            "model": get_base_model_name(model),
            "project": proj_id,
            "request": payload.get("request", {}),
        }

        action = "streamGenerateContent" if is_streaming else "generateContent"
        target_url = f"{CODE_ASSIST_ENDPOINT}/v1internal:{action}"
        if is_streaming:
            target_url += "?alt=sse"

        headers = {
            "Authorization": f"Bearer {creds.token}",
            "Content-Type": "application/json",
            "User-Agent": get_user_agent(),
        }

        post_data = json.dumps(final_payload)
        logging.info(
            f"Dispatching request for model={model} (streaming={is_streaming}) to project={proj_id} with cred={cred_id}"
        )

        timeouts = self.settings["request_timeouts"]
        timeout_tuple = (timeouts["connect"], timeouts["read"])

        max_retries = 3
        for attempt in range(max_retries):
            try:
                if is_streaming:
                    resp = requests.post(
                        target_url,
                        data=post_data,
                        headers=headers,
                        stream=True,
                        timeout=timeout_tuple,
                    )
                else:
                    resp = requests.post(
                        target_url,
                        data=post_data,
                        headers=headers,
                        timeout=timeout_tuple,
                    )

                if resp.status_code == 429 or resp.status_code == 403:
                    if resp.status_code == 429:
                        logging.warning(
                            f"Received 429 (Rate Limit Exceeded) for credential {cred_id} "
                            f"(email: {getattr(managed, 'email', 'N/A')}, model: {model}) on attempt {attempt + 1}. Rotating credential."
                        )
                        self.credential_manager.mark_exhausted(cred_id)
                    else:  # 403
                        logging.error(
                            f"Received 403 (Forbidden) for credential {cred_id} "
                            f"(email: {getattr(managed, 'email', 'N/A')}, project: {proj_id}, model: {model}). "
                            "This indicates a permanent permission issue. Marking credential as invalid and rotating."
                        )
                        self.credential_manager.mark_as_invalid(cred_id)

                    if attempt == max_retries - 1:
                        logging.error(
                            f"All retry attempts exhausted for credential {cred_id} after {resp.status_code} error."
                        )
                        return (
                            self._handle_streaming_response(
                                resp, auth_key, cred_id, model
                            )
                            if is_streaming
                            else self._handle_non_streaming_response(
                                resp, auth_key, cred_id, model
                            )
                        )

                    new_managed = self.credential_manager.get_available()
                    if new_managed:
                        managed = new_managed
                        creds = managed.credentials
                        proj_id = managed.project_id
                        cred_id = managed.id
                        logging.info(
                            f"Switching to new credential id={cred_id} for retry."
                        )
                        headers["Authorization"] = f"Bearer {creds.token}"
                        final_payload["project"] = proj_id
                        post_data = json.dumps(final_payload)
                        continue
                    else:
                        logging.error(
                            f"No more available credentials to rotate to after {resp.status_code} error."
                        )
                        return (
                            self._handle_streaming_response(
                                resp, auth_key, cred_id, model
                            )
                            if is_streaming
                            else self._handle_non_streaming_response(
                                resp, auth_key, cred_id, model
                            )
                        )
                else:
                    if is_streaming:
                        logging.debug(
                            "Upstream responded for streaming; starting SSE relay"
                        )
                        return self._handle_streaming_response(
                            resp, auth_key, cred_id, model
                        )
                    else:
                        return self._handle_non_streaming_response(
                            resp, auth_key, cred_id, model
                        )
            except requests.exceptions.RequestException as e:
                logging.error(f"Request to Google API failed: {e}")
                return Response(
                    content=json.dumps({"error": {"message": f"Request failed: {e}"}}),
                    status_code=500,
                    media_type="application/json",
                )
            except Exception as e:
                logging.error(f"Unexpected error during Google API request: {e}")
                return Response(
                    content=json.dumps(
                        {"error": {"message": f"Unexpected error: {e}"}}
                    ),
                    status_code=500,
                    media_type="application/json",
                )

        return Response(
            content=json.dumps({"error": {"message": "Request failed after retries"}}),
            status_code=500,
            media_type="application/json",
        )

    def _handle_streaming_response(
        self, resp, auth_key: str, cred_id: str, model_name: str
    ) -> StreamingResponse:
        """
        处理来自 Google API 的流式响应 (SSE)。

        此方法会逐块读取服务器发送的事件流，解析数据，并将其转发给客户端。
        在流结束时，它会尝试解析用量元数据 (usageMetadata) 并记录到 UsageTracker。
        如果在处理过程中发生错误，它会生成一个错误事件流。

        Args:
            resp: 来自 requests 的响应对象，stream=True。
            auth_key (str): 用于标识请求来源的认证密钥。
            cred_id (str): 当前使用的凭据 ID，用于日志和用量统计。
            model_name (str): 请求的模型名称，用于用量统计。

        Returns:
            StreamingResponse: FastAPI 的 StreamingResponse 对象，将流式数据转发给客户端。
        """
        from .state import usage_tracker

        if resp.status_code != 200:
            # 对于失败的响应，也尝试解析错误信息并记录失败
            try:
                error_data = resp.json()
                reason = error_data.get("error", {}).get("status", "UNKNOWN")
                if usage_tracker:
                    usage_tracker.record_failed_request(
                        auth_key,
                        cred_id,
                        model_name,
                        f"HTTP_{resp.status_code}_{reason}",
                    )
                err_msg = error_data.get("error", {}).get(
                    "message", f"Google API error: {resp.status_code}"
                )
            except Exception:
                err_msg = f"Google API error: {resp.status_code}"
                if usage_tracker:
                    usage_tracker.record_failed_request(
                        auth_key, cred_id, model_name, f"HTTP_{resp.status_code}"
                    )

            async def error_gen():
                logging.error(f"Upstream streaming error: {err_msg}")
                yield f"data: {json.dumps({'error': {'message': err_msg}})}\n\n".encode(
                    "utf-8"
                )
                yield "data: [DONE]\n\n".encode("utf-8")

            return StreamingResponse(
                error_gen(),
                media_type="text/event-stream",
                status_code=resp.status_code,
            )

        async def stream_gen():
            from .state import usage_tracker

            logging.debug(
                f"Begin SSE relay from upstream for cred={cred_id}, model={model_name}"
            )
            usage_metadata = None
            start_time = time.time()
            try:
                with resp:
                    for chunk in resp.iter_lines():
                        if not chunk:
                            continue
                        chunk = chunk.decode("utf-8", "ignore")

                        if chunk.startswith("data: "):
                            chunk_data = chunk[len("data: ") :]
                            try:
                                obj = json.loads(chunk_data)
                                logging.debug(f"Stream chunk received: {obj}")

                                response_obj = obj.get("response", {})
                                if "usageMetadata" in response_obj:
                                    # 仅当包含详细token计数时才认为是有效的元数据
                                    if (
                                        "totalTokenCount"
                                        in response_obj["usageMetadata"]
                                    ):
                                        usage_metadata = response_obj["usageMetadata"]

                                if "response" in obj:
                                    response_chunk = obj["response"]
                                    yield f"data: {json.dumps(response_chunk, separators=(',', ':'))}\n\n".encode(
                                        "utf-8"
                                    )
                                else:
                                    yield f"data: {json.dumps(obj, separators=(',', ':'))}\n\n".encode(
                                        "utf-8"
                                    )
                                await asyncio.sleep(0)
                            except json.JSONDecodeError:
                                logging.warning(
                                    f"Failed to decode stream chunk as JSON: {chunk_data}"
                                )
                                continue
            except requests.exceptions.RequestException as e:
                err = {
                    "error": {
                        "message": f"Upstream request failed: {e}",
                        "type": "api_error",
                        "code": 502,
                    }
                }
                logging.error(
                    f"Streaming request failed for cred={cred_id}, model={model_name}: {e}"
                )
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8", "ignore")
            except Exception as e:
                err = {
                    "error": {
                        "message": f"Unexpected error: {e}",
                        "type": "api_error",
                        "code": 500,
                    }
                }
                logging.error(
                    f"Streaming unexpected error for cred={cred_id}, model={model_name}: {e}"
                )
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8", "ignore")
            finally:
                logging.debug(
                    f"Stream finished. Usage metadata found: {usage_metadata is not None}"
                )
                if usage_tracker and usage_metadata:
                    logging.debug(f"Recording usage metadata: {usage_metadata}")
                    usage_tracker.record_successful_request(
                        auth_key, cred_id, model_name, usage_metadata
                    )
                duration = time.time() - start_time
                logging.info(
                    f"Finished request for cred={cred_id}, model={model_name} in {duration:.2f} seconds."
                )

        return StreamingResponse(stream_gen(), media_type="text/event-stream")

    def _handle_non_streaming_response(
        self, resp, auth_key: str, cred_id: str, model_name: str
    ) -> Response:
        """
        处理来自 Google API 的非流式响应。

        此方法会解析完整的 JSON 响应，提取标准响应体，并尝试解析用量元数据 (usageMetadata)
        记录到 UsageTracker。如果响应包含错误，它会进行相应的错误处理和格式化。

        Args:
            resp: 来自 requests 的响应对象。
            auth_key (str): 用于标识请求来源的认证密钥。
            cred_id (str): 当前使用的凭据 ID，用于用量统计。
            model_name (str): 请求的模型名称，用于用量统计。

        Returns:
            Response: FastAPI 的 Response 对象，包含格式化后的响应数据或错误信息。
        """
        from .state import usage_tracker

        if resp.status_code == 200:
            try:
                text = resp.text
                if text.startswith("data: "):
                    text = text[len("data: ") :]
                obj = json.loads(text)
                logging.debug(f"Non-stream response object for usage parsing: {obj}")

                if usage_tracker:
                    prompt_feedback = obj.get("promptFeedback", {})
                    if prompt_feedback.get("blockReason"):
                        usage_tracker.record_failed_request(
                            auth_key,
                            cred_id,
                            model_name,
                            prompt_feedback.get("blockReason"),
                        )
                    else:
                        usage_metadata = obj.get("usageMetadata")
                        usage_tracker.record_successful_request(
                            auth_key, cred_id, model_name, usage_metadata or {}
                        )
                        if usage_metadata:
                            logging.info(
                                f"Usage recorded for non-stream request {auth_key}/{cred_id}/{model_name}"
                            )

                standard = obj.get("response", obj)
                return Response(
                    content=json.dumps(standard),
                    status_code=200,
                    media_type="application/json; charset=utf-8",
                )
            except Exception as e:
                logging.error(f"Error processing non-stream response: {e}")
                # 即使处理成功响应时出错，也应返回原始响应
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    media_type=resp.headers.get("Content-Type"),
                )
        else:
            # 记录失败请求
            try:
                data = resp.json()
                reason = data.get("error", {}).get("status", "UNKNOWN")
                if usage_tracker:
                    usage_tracker.record_failed_request(
                        auth_key,
                        cred_id,
                        model_name,
                        f"HTTP_{resp.status_code}_{reason}",
                    )
                err_msg = data.get("error", {}).get(
                    "message", f"API error: {resp.status_code}"
                )
                err = {
                    "error": {
                        "message": err_msg,
                        "type": "api_error",
                        "code": resp.status_code,
                    }
                }
                return Response(
                    content=json.dumps(err),
                    status_code=resp.status_code,
                    media_type="application/json",
                )
            except Exception:
                if usage_tracker:
                    usage_tracker.record_failed_request(
                        auth_key, cred_id, model_name, f"HTTP_{resp.status_code}"
                    )
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    media_type=resp.headers.get("Content-Type"),
                )

    def _sse_error(self, message: str, status_code: int = 500) -> StreamingResponse:
        async def gen():
            yield f"data: {json.dumps({'error': {'message': message, 'code': status_code}})}\n\n".encode(
                "utf-8"
            )
            yield f"data: [DONE]\n\n".encode("utf-8")

        logging.error(f"Returning SSE error: {message} ({status_code})")
        return StreamingResponse(
            gen(), media_type="text/event-stream", status_code=status_code
        )
