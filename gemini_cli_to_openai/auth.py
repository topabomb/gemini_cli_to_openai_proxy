"""
认证与 OAuth 流程：
- 鉴权依赖：支持 key、x-goog-api-key、Bearer、Basic，密码来自配置。
- OAuth 浏览器流程：获取 Credentials 后仅持久化四字段。
- onboard 与 project_id 发现逻辑复用，移除环境变量依赖。
"""
import base64
import json
import logging
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional

import requests
from fastapi import HTTPException, Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest

from .config import CLIENT_ID, CLIENT_SECRET, SCOPES, CODE_ASSIST_ENDPOINT
from .utils import get_user_agent, get_client_metadata
from .credentials import _credentials_to_simple


def authenticate_request(request: Request, password: str) -> str:
    """统一鉴权：返回用户名或声明字符串。"""
    # query 参数 key
    api_key = request.query_params.get("key")
    if api_key and api_key == password:
        return "api_key_user"

    # x-goog-api-key 头
    gk = request.headers.get("x-goog-api-key", "")
    if gk and gk == password:
        return "goog_api_key_user"

    # Authorization Bearer
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token == password:
            return "bearer_user"

    # HTTP Basic
    if auth_header.startswith("Basic "):
        try:
            encoded = auth_header[6:]
            decoded = base64.b64decode(encoded).decode("utf-8", "ignore")
            username, pwd = decoded.split(":", 1)
            if pwd == password:
                return username
        except Exception:
            pass

    raise HTTPException(
        status_code=401,
        detail="Invalid authentication credentials. Use HTTP Basic, Bearer, ?key= or x-goog-api-key.",
        headers={"WWW-Authenticate": "Basic"},
    )


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    auth_code: Optional[str] = None
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        code = parse_qs(urlparse(self.path).query).get("code", [None])[0]
        if code:
            _OAuthCallbackHandler.auth_code = code
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>OAuth authentication successful!</h1><p>You can close this window.</p>")
        else:
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Authentication failed.</h1>")


def run_oauth_flow() -> Optional[Credentials]:
    """执行 OAuth 流程并返回 Credentials（使用动态端口与显式关闭，避免端口占用导致卡顿）。"""
    # 重置回调码，避免脏数据
    _OAuthCallbackHandler.auth_code = None

    # 启动本地回调监听（动态端口）
    server = HTTPServer(("127.0.0.1", 0), _OAuthCallbackHandler)
    server.timeout = 1
    port = server.server_address[1]
    logging.info(f"OAuth callback listener started on http://127.0.0.1:{port}")

    # 构造 OAuth Flow（使用动态回调 URI）
    client_config = {
        "installed": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    redirect_uri = f"http://127.0.0.1:{port}"
    flow = Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=redirect_uri)
    flow.oauth2session.scope = SCOPES
    auth_url, _ = flow.authorization_url(access_type="offline", prompt="consent", include_granted_scopes="true")

    # 提示用户登录
    print("\n" + "="*80)
    print("AUTHENTICATION REQUIRED")
    print("="*80)
    print("Please open this URL in your browser to log in:")
    print(auth_url)
    print("="*80 + "\n")

    # 等待回调（轮询 handle_request，带超时与日志）
    import time as _time
    start_ts = _time.time()
    max_wait = 300  # 5 分钟超时
    try:
        while _OAuthCallbackHandler.auth_code is None and (_time.time() - start_ts) < max_wait:
            server.handle_request()
        code = _OAuthCallbackHandler.auth_code
    finally:
        try:
            server.server_close()
        except Exception:
            pass

    if not code:
        logging.error("OAuth callback not received within timeout")
        return None

    # 容忍参数校验告警
    import oauthlib.oauth2.rfc6749.parameters
    original_validate = oauthlib.oauth2.rfc6749.parameters.validate_token_parameters
    def patched_validate(params):
        try:
            return original_validate(params)
        except Warning:
            pass
    oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = patched_validate

    # 交换 token
    fetch_start = _time.time()
    logging.info("Exchanging authorization code for tokens...")
    try:
        flow.fetch_token(code=code)
        logging.info(f"Token exchange finished in {int((_time.time()-fetch_start)*1000)} ms")
        return flow.credentials
    finally:
        oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = original_validate


def onboard_user(creds: Credentials, project_id: str):
    """执行用户上船，与 src/auth.py 一致。"""
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleAuthRequest())
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }
    load_payload = {"cloudaicompanionProject": project_id, "metadata": get_client_metadata(project_id)}
    try:
        resp = requests.post(f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist", data=json.dumps(load_payload), headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        tier = data.get("currentTier")
        if not tier:
            for t in data.get("allowedTiers", []):
                if t.get("isDefault"):
                    tier = t
                    break
            if not tier:
                tier = {"id": "legacy-tier", "userDefinedCloudaicompanionProject": True}
        if tier.get("userDefinedCloudaicompanionProject") and not project_id:
            raise ValueError("This account requires setting project_id in config project_id_map.")

        if data.get("currentTier"):
            return

        onboard_payload = {"tierId": tier.get("id"), "cloudaicompanionProject": project_id, "metadata": get_client_metadata(project_id)}
        while True:
            r = requests.post(f"{CODE_ASSIST_ENDPOINT}/v1internal:onboardUser", data=json.dumps(onboard_payload), headers=headers, timeout=20)
            r.raise_for_status()
            lro = r.json()
            if lro.get("done"):
                break
            time.sleep(5)
    except requests.exceptions.HTTPError as e:
        raise Exception(f"User onboarding failed: {e.response.text if hasattr(e, 'response') else str(e)}")


def save_credentials_simple(path: str, creds_list: list):
    """以四字段格式保存多个凭据。"""
    out = creds_list if len(creds_list) > 1 else (creds_list[0] if creds_list else [])
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)


