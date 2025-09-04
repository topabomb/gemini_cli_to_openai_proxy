"""
Google API 客户端：
- 迁移自 src/google_api_client.py，统一从 CredentialManager 获取凭据。
- 保持非流式与流式（SSE）转发逻辑、429 重试与轮转策略不变。
"""
import json
import logging
import asyncio
from typing import Dict

import requests
from fastapi import Response
from fastapi.responses import StreamingResponse

from .config import CODE_ASSIST_ENDPOINT, DEFAULT_SAFETY_SETTINGS, get_base_model_name, is_search_model, get_thinking_budget, should_include_thoughts
from .utils import get_user_agent
from .credentials import CredentialManager


class ApiClient:
    def __init__(self, cred_manager: CredentialManager):
        self.credential_manager = cred_manager

    def send_gemini_request(self, payload: Dict, is_streaming: bool = False) -> Response:
        model = payload.get("model")
        logging.info(f"Preparing request: model={model}, streaming={is_streaming}")
        managed = self.credential_manager.get_available()
        if not managed:
            logging.error("No valid credentials available")
            if is_streaming:
                return self._sse_error("No valid credentials available.", 500)
            return Response(content=json.dumps({"error": {"message": "No valid credentials available.", "code": 500}}), status_code=500, media_type="application/json")

        creds = managed.credentials
        proj_id = managed.project_id
        cred_id = managed.id
        logging.info(f"Using credential: id={cred_id}, email={getattr(managed, 'email', None)}, project={proj_id}")

        if getattr(creds, 'expiry', None) is not None:
            # 统一比较使用 naive UTC
            try:
                from datetime import timezone
                if creds.expiry.tzinfo is not None:
                    exp_naive = creds.expiry.astimezone(timezone.utc).replace(tzinfo=None)
                else:
                    exp_naive = creds.expiry
                from datetime import datetime
                now_naive = datetime.utcnow()
                expired_flag = exp_naive <= now_naive
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
                            return self._sse_error("No valid credentials after refresh.", 500)
                        return Response(content=json.dumps({"error": {"message": "No valid credentials after refresh.", "code": 500}}), status_code=500, media_type="application/json")
                    creds = managed.credentials
                    proj_id = managed.project_id
                    cred_id = managed.id
            except Exception as e:
                logging.error(f"Token refresh failed for {cred_id}: {e}")
                managed = self.credential_manager.get_available()
                if not managed:
                    if is_streaming:
                        return self._sse_error("Token refresh failed.", 500)
                    return Response(content=json.dumps({"error": {"message": "Token refresh failed.", "code": 500}}), status_code=500, media_type="application/json")
                creds = managed.credentials
                proj_id = managed.project_id
                cred_id = managed.id

        if not creds.token:
            managed = self.credential_manager.get_available()
            if not managed:
                logging.error("No access token")
                if is_streaming:
                    return self._sse_error("No access token.", 500)
                return Response(content=json.dumps({"error": {"message": "No access token.", "code": 500}}), status_code=500, media_type="application/json")
            creds = managed.credentials
            proj_id = managed.project_id
            cred_id = managed.id

        final_payload = {
            "model": payload.get("model"),
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
        logging.info(f"Dispatching to {target_url} with project={proj_id}")

        max_retries = 3
        for attempt in range(max_retries):
            try:
                if is_streaming:
                    resp = requests.post(target_url, data=post_data, headers=headers, stream=True)
                else:
                    resp = requests.post(target_url, data=post_data, headers=headers)

                if resp.status_code == 429:
                    logging.warning(f"Received 429 for credential {cred_id} on attempt {attempt + 1}")
                    self.credential_manager.mark_exhausted(cred_id)
                    if attempt == max_retries - 1:
                        logging.error(f"All retry attempts exhausted for credential {cred_id}")
                        if is_streaming:
                            return self._handle_streaming_response(resp)
                        else:
                            return self._handle_non_streaming_response(resp)
                    new_managed = self.credential_manager.get_available()
                    if new_managed:
                        managed = new_managed
                        creds = managed.credentials
                        proj_id = managed.project_id
                        cred_id = managed.id
                        logging.info(f"Switching credential to id={cred_id}, email={getattr(managed, 'email', None)}, project={proj_id}")
                        headers["Authorization"] = f"Bearer {creds.token}"
                        final_payload["project"] = proj_id
                        post_data = json.dumps(final_payload)
                        continue
                else:
                    if is_streaming:
                        logging.info("Upstream responded for streaming; starting SSE relay")
                        return self._handle_streaming_response(resp)
                    else:
                        return self._handle_non_streaming_response(resp)
            except requests.exceptions.RequestException as e:
                logging.error(f"Request to Google API failed: {e}")
                return Response(content=json.dumps({"error": {"message": f"Request failed: {e}"}}), status_code=500, media_type="application/json")
            except Exception as e:
                logging.error(f"Unexpected error during Google API request: {e}")
                return Response(content=json.dumps({"error": {"message": f"Unexpected error: {e}"}}), status_code=500, media_type="application/json")

        return Response(content=json.dumps({"error": {"message": "Request failed after retries"}}), status_code=500, media_type="application/json")

    def _handle_streaming_response(self, resp) -> StreamingResponse:
        if resp.status_code != 200:
            try:
                err_msg = f"Google API error: {resp.status_code}"
                data = resp.json()
                if "error" in data:
                    err_msg = data["error"].get("message", err_msg)
            except Exception:
                err_msg = f"Google API error: {resp.status_code}"

            async def error_gen():
                logging.error(f"Upstream streaming error: {err_msg}")
                yield f"data: {json.dumps({'error': {'message': err_msg}})}\n\n".encode("utf-8")
            return StreamingResponse(error_gen(), media_type="text/event-stream", status_code=resp.status_code)

        async def stream_gen():
            logging.info("Begin SSE relay from upstream")
            try:
                with resp:
                    for chunk in resp.iter_lines():
                        if not chunk:
                            continue
                        if not isinstance(chunk, str):
                            chunk = chunk.decode("utf-8", "ignore")
                        if chunk.startswith("data: "):
                            chunk = chunk[len("data: ") :]
                            try:
                                obj = json.loads(chunk)
                                if "response" in obj:
                                    response_chunk = obj["response"]
                                    yield f"data: {json.dumps(response_chunk, separators=(',', ':'))}\n\n".encode("utf-8", "ignore")
                                    await asyncio.sleep(0)
                                else:
                                    yield f"data: {json.dumps(obj, separators=(',', ':'))}\n\n".encode("utf-8", "ignore")
                            except json.JSONDecodeError:
                                continue
            except requests.exceptions.RequestException as e:
                err = {"error": {"message": f"Upstream request failed: {e}", "type": "api_error", "code": 502}}
                logging.error(f"Streaming request failed: {e}")
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8", "ignore")
            except Exception as e:
                err = {"error": {"message": f"Unexpected error: {e}", "type": "api_error", "code": 500}}
                logging.error(f"Streaming unexpected error: {e}")
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8", "ignore")

        return StreamingResponse(stream_gen(), media_type="text/event-stream")

    def _handle_non_streaming_response(self, resp) -> Response:
        if resp.status_code == 200:
            try:
                text = resp.text
                if text.startswith("data: "):
                    text = text[len("data: ") :]
                obj = json.loads(text)
                standard = obj.get("response")
                return Response(content=json.dumps(standard), status_code=200, media_type="application/json; charset=utf-8")
            except Exception:
                return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("Content-Type"))
        else:
            try:
                data = resp.json()
                if "error" in data:
                    err = {
                        "error": {
                            "message": data["error"].get("message", f"API error: {resp.status_code}"),
                            "type": "invalid_request_error" if resp.status_code == 404 else "api_error",
                            "code": resp.status_code,
                        }
                    }
                    return Response(content=json.dumps(err), status_code=resp.status_code, media_type="application/json")
            except Exception:
                pass
            return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("Content-Type"))


    def _sse_error(self, message: str, status_code: int = 500) -> StreamingResponse:
        async def gen():
            yield f"data: {json.dumps({'error': {'message': message, 'code': status_code}})}\n\n".encode("utf-8")
            yield f"data: [DONE]\n\n".encode("utf-8")
        logging.error(f"Returning SSE error: {message} ({status_code})")
        return StreamingResponse(gen(), media_type="text/event-stream", status_code=status_code)

def build_gemini_payload_from_openai(openai_payload: dict) -> dict:
    model = openai_payload.get("model")
    safety_settings = openai_payload.get("safetySettings", DEFAULT_SAFETY_SETTINGS)
    request_data = {
        "contents": openai_payload.get("contents"),
        "systemInstruction": openai_payload.get("systemInstruction"),
        "cachedContent": openai_payload.get("cachedContent"),
        "tools": openai_payload.get("tools"),
        "toolConfig": openai_payload.get("toolConfig"),
        "safetySettings": safety_settings,
        "generationConfig": openai_payload.get("generationConfig", {}),
    }
    request_data = {k: v for k, v in request_data.items() if v is not None}
    return {"model": model, "request": request_data}


def build_gemini_payload_from_native(native_request: dict, model_from_path: str) -> dict:
    native_request["safetySettings"] = DEFAULT_SAFETY_SETTINGS
    if "generationConfig" not in native_request:
        native_request["generationConfig"] = {}
    if "thinkingConfig" not in native_request["generationConfig"]:
        native_request["generationConfig"]["thinkingConfig"] = {}
    thinking_budget = get_thinking_budget(model_from_path)
    include_thoughts = should_include_thoughts(model_from_path)
    native_request["generationConfig"]["thinkingConfig"]["includeThoughts"] = include_thoughts
    if "thinkingBudget" in native_request["generationConfig"]["thinkingConfig"] and thinking_budget == -1:
        pass
    else:
        native_request["generationConfig"]["thinkingConfig"]["thinkingBudget"] = thinking_budget
    if is_search_model(model_from_path):
        if "tools" not in native_request:
            native_request["tools"] = []
        if not any(tool.get("googleSearch") for tool in native_request["tools"]):
            native_request["tools"].append({"googleSearch": {}})
    return {"model": get_base_model_name(model_from_path), "request": native_request}


