"""
管理路由模块：
- 提供 Web UI 入口、健康检查。
- 实现 OAuth2 认证流程。
- 提供凭据和用量查询的 API 端点。
"""

import logging
from fastapi import APIRouter, Request, Depends

logger = logging.getLogger(__name__)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from google_auth_oauthlib.flow import Flow
import asyncio
import oauthlib.oauth2.rfc6749.parameters

from ...core.config import CLIENT_ID, CLIENT_SECRET, SCOPES
from ...services.credential_manager import CredentialManager
from ..dependencies import get_credential_manager

router = APIRouter(tags=["Admin & OAuth"])

@router.get("/", response_class=HTMLResponse)
async def get_admin_ui():
    """提供一个简单的 HTML 管理界面。"""
    content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gemini API Proxy Management</title>
        <style>
            body { font-family: sans-serif; margin: 2em; }
            h1, h2 { color: #333; }
            a { color: #007bff; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .container { max-width: 800px; margin: auto; }
            .card { border: 1px solid #ddd; padding: 1em; margin-bottom: 1em; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Gemini API Proxy Management</h1>
            <div class="card">
                <h2>Add New Credential</h2>
                <p>Click the link below to start the Google OAuth2 process and add a new credential to the pool.</p>
                <a href="/oauth2/login"><strong>Start Authentication</strong></a>
            </div>
            <div class="card">
                <h2>Monitor Service</h2>
                <p>Check the status of credentials and API usage.</p>
                <ul>
                    <li><a href="/admin/credentials" target="_blank">View Credentials Status</a></li>
                    <li><a href="/admin/usage" target="_blank">View Usage Stats</a></li>
                    <li><a href="/health" target="_blank">Health Check</a></li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=content)

@router.get("/health")
async def health_check():
    """健康检查端点。"""
    return {"status": "healthy"}

@router.get("/oauth2/login")
async def oauth2_login(request: Request):
    """重定向到 Google 授权页面。"""
    settings = request.app.state.settings
    public_url = settings.get("public_url")

    # 优先使用 public_url 构建回调 URI
    if public_url:
        redirect_uri = public_url.rstrip('/') + '/oauth2/callback'
    else:
        # 否则，回退到从请求头推断，方便本地使用
        host = request.headers.get("host", "localhost")
        scheme = request.url.scheme
        redirect_uri = f"{scheme}://{host}/oauth2/callback"
    
    logger.info(f"Starting OAuth flow with redirect_uri: {redirect_uri}")

    flow = Flow.from_client_config(
        client_config={
            "installed": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true"
    )
    
    # 将 flow 和 state 存储在应用状态中以便回调时使用
    # 注意：在多实例部署中，这需要一个共享的存储（如 Redis）
    request.app.state.oauth_flow = flow
    
    return RedirectResponse(authorization_url)

@router.get("/oauth2/callback", response_class=HTMLResponse)
async def oauth2_callback(request: Request, code: str, cred_manager: CredentialManager = Depends(get_credential_manager)):
    """处理 Google OAuth2 回调。"""
    flow = getattr(request.app.state, "oauth_flow", None)
    if not flow:
        return HTMLResponse("<h1>Error: OAuth flow not found. Please start again.</h1>", status_code=400)

    # 猴子补丁以容忍 scope change 警告
    original_validate = oauthlib.oauth2.rfc6749.parameters.validate_token_parameters
    def patched_validate(params):
        try:
            return original_validate(params)
        except Warning:
            pass # 忽略警告
    oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = patched_validate
    
    try:
        # 在线程池中运行同步的 fetch_token，使用 lambda 确保 code 作为关键字参数传递
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: flow.fetch_token(code=code))
        
        creds = flow.credentials
        ok, reason = await cred_manager.add_or_update_credential(creds)
    finally:
        # 恢复原始的验证函数
        oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = original_validate
        
    if ok:
        return HTMLResponse("<h1>Authentication Successful!</h1><p>You can close this window now.</p>")
    else:
        return HTMLResponse(f"<h1>Authentication Failed</h1><p>Reason: {reason}. Please try again.</p>", status_code=400)

@router.get("/admin/credentials")
async def get_credentials_status(cred_manager: CredentialManager = Depends(get_credential_manager)):
    """获取所有凭据的状态。"""
    details = cred_manager.get_all_credential_details()
    return JSONResponse(content=details)

@router.get("/admin/usage")
async def get_usage_status(request: Request):
    """获取用量统计。"""
    usage_tracker = request.app.state.usage_tracker
    summary = await usage_tracker.get_usage_snapshot()
    return JSONResponse(content=summary)
