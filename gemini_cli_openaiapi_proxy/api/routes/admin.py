"""
管理路由模块：
- 提供 Web UI 入口、健康检查。
- 实现 OAuth2 认证流程。
- 提供凭据和用量查询的 API 端点。
"""

import logging
from typing import Any, Dict, cast
from fastapi import APIRouter, Request, Depends,HTTPException

logger = logging.getLogger(__name__)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest
import asyncio
import oauthlib.oauth2.rfc6749.parameters

from ...core.config import CLIENT_ID, CLIENT_SECRET, SCOPES
from ...services.credential_manager import CredentialManager
from ...services.usage_tracker import UsageTracker, _format_human_readable
from ..dependencies import get_credential_manager, get_usage_tracker
from ..security import verify_admin_access
from ...utils.credential_tools import AddCredentialRequest, build_credentials_from_simple

router = APIRouter(
    tags=["Admin & OAuth"],
    dependencies=[Depends(verify_admin_access)]
)

@router.get("/", response_class=HTMLResponse)
async def get_admin_ui(
    cred_manager: CredentialManager = Depends(get_credential_manager),
    usage_tracker: UsageTracker = Depends(get_usage_tracker)
):
    """提供一个包含实时统计信息的 HTML 管理界面。"""
    
    all_creds = cred_manager.get_all_credential_details()
    total_creds = len(all_creds)
    active_creds = sum(1 for c in all_creds if c.get("is_available"))
    inactive_creds = total_creds - active_creds
    
    # --- 生成凭据表格 ---
    credentials_table_rows = ""
    if not all_creds:
        credentials_table_rows = '<tr><td colspan="7" style="text-align: center;">No credentials available.</td></tr>'
    else:
        for cred in all_creds:
            cred_id = cred.get('id', 'N/A')
            email = cred.get('email', 'N/A')
            project_id = cred.get('project_id', 'N/A')
            
            credentials_table_rows += f"""
                <tr id="cred-row-{cred_id}">
                    <td>{cred_id}</td>
                    <td>{email}</td>
                    <td>{project_id}</td>
                    <td>{cred.get('status', 'UNKNOWN')}</td>
                    <td>{cred.get('expiry', 'N/A')}</td>
                    <td>{cred.get('last_used_at', 'N/A')}</td>
                    <td>
                        <a href="/admin/credentials/{cred_id}/check" target="_blank" class="button">Check</a>
                        <span onclick="deleteCredential('{cred_id}')" class="button">Delete</span>
                    </td>
                </tr>
            """

    # --- 生成用量表格 ---
    usage_summary = await usage_tracker.get_aggregated_usage_summary()
    usage_table_rows = ""
    if not usage_summary:
        usage_table_rows = '<tr><td colspan="5" style="text-align: center;">No usage data recorded yet.</td></tr>'
    else:
        for model, stats in usage_summary.items():
            usage_table_rows += f"""
                <tr>
                    <td>{model}</td>
                    <td>{_format_human_readable(stats.get('successful_requests', 0))}</td>
                    <td>{_format_human_readable(stats.get('prompt_tokens', 0))}</td>
                    <td>{_format_human_readable(stats.get('candidates_tokens', 0))}</td>
                    <td>{_format_human_readable(stats.get('total_tokens', 0))}</td>
                </tr>
            """

    # --- 组装完整 HTML ---
    content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Model API Proxy Management</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.1; color: #333; }}
            h2, h4 {{ margin: 0.6em 0 0.4em 0; }}
            h4 {{ border-top: 1px solid #eee; padding-top: 0.6em; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 6px 8px; text-align: left; font-size: 0.9em; vertical-align: middle; }}
            th {{ background-color: #f8f8f8; }}
            ul {{ padding-left: 20px; margin: 0.5em 0; }}
            .summary {{ text-align: right; font-size: 0.9em; margin: 0.5em 0 1.5em 0; }}
            .button {{
                display: inline-block;
                background-color: #f0f0f0;
                color: #333;
                text-decoration: none;
                border: 1px solid #ccc;
                border-radius: 4px;
                cursor: pointer;
                padding: 4px 8px;
                font-size: 0.9em;
            }}
            .button:hover {{ background-color: #e0e0e0; }}
        </style>
    </head>
    <body>
        <h2>Model API Proxy Management</h2>

        <h4>Managed Credentials</h4>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Email</th>
                    <th>Project ID</th>
                    <th>Status</th>
                    <th>Expiry</th>
                    <th>Last Used</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {credentials_table_rows}
            </tbody>
        </table>
        <div class="summary">
            <strong>Total:</strong> {total_creds} | <strong>Available:</strong> {active_creds} | <strong>Inactive:</strong> {inactive_creds}
        </div>

        <h4>Usage by Model</h4>
        <table>
            <thead>
                <tr>
                    <th>Model</th>
                    <th>Requests</th>
                    <th>Prompt Tokens</th>
                    <th>Output Tokens</th>
                    <th>Total Tokens</th>
                </tr>
            </thead>
            <tbody>
                {usage_table_rows}
            </tbody>
        </table>

        <h4>Actions</h4>
        <a href="/oauth2/login" target="_blank" class="button" style="font-weight: bold; padding: 6px 12px;">Start Authentication</a>

        <h4>Endpoints</h4>
        <ul>
            <li><a href="/admin/credentials">View Credentials Status (JSON)</a></li>
            <li><a href="/admin/usage">View Usage Stats (JSON)</a></li>
        </ul>

        <script>
            function deleteCredential(credentialId) {{
                if (confirm(`Are you sure you want to delete credential: ${{credentialId}}?`)) {{
                    fetch(`/admin/credentials/${{credentialId}}`, {{
                        method: 'DELETE',
                    }})
                    .then(response => {{
                        if (response.ok) {{
                            const row = document.getElementById(`cred-row-${{credentialId}}`);
                            if (row) row.remove();
                            alert('Credential deleted successfully.');
                            window.location.reload(); // Reload to update summary stats
                        }} else {{
                            response.json().then(data => {{
                                alert(`Failed to delete credential: ${{data.detail || "Unknown error"}}`);
                            }});
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error:', error);
                        alert('An error occurred while trying to delete the credential.');
                    }});
                }}
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=content)

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
async def get_usage_status(usage_tracker: UsageTracker = Depends(get_usage_tracker)):
    """获取聚合后的用量统计，不暴露任何敏感分组信息。"""
    summary = await usage_tracker.get_aggregated_usage_summary()
    return JSONResponse(content=summary)

@router.get("/admin/credentials/{credential_id}/check")
async def force_credential_health_check(
    credential_id: str,
    cred_manager: CredentialManager = Depends(get_credential_manager)
):
    """强制对单个凭据执行健康检查并返回详细结果。"""
    result = await cred_manager.force_health_check(credential_id)
    status_code = 404 if "error" in result else 200
    return JSONResponse(content=result, status_code=status_code)

@router.post(
    "/admin/credentials/add",
    summary="Add or update a credential via API",
    tags=["Admin & OAuth"],
    dependencies=[Depends(verify_admin_access)],
    responses={
        200: {"description": "Credential added or updated successfully."},
        400: {"description": "Invalid request or credential data."},
        401: {"description": "Authentication failed."},
    }
)
async def add_credential_api(
    payload: AddCredentialRequest,
    cred_manager: CredentialManager = Depends(get_credential_manager)
):
    """
    通过 API 接收一个序列化的凭据（其中可能包含 project_id）并将其添加到池中。
    此端点受管理员 Basic Auth 保护。
    """
    # project_id 现在是凭据负载本身的一部分。
    project_id_from_payload = payload.credential.get("project_id")
    
    creds = build_credentials_from_simple(payload.credential)

    ok, reason = await cred_manager.add_or_update_credential(creds, project_id_override=project_id_from_payload)

    if ok:
        email = "N/A"
        all_creds = cred_manager.get_all_credential_details()
        if all_creds:
            # 假设新添加的总是最后一个
            email = all_creds[-1].get("email", "N/A")
        
        return JSONResponse(
            status_code=200,
            content={"status": "success", "message": reason, "email": email}
        )
    else:
        raise HTTPException(status_code=400, detail=reason)

@router.delete(
    "/admin/credentials/{credential_id}",
    summary="Delete a credential",
    tags=["Admin & OAuth"],
    status_code=200,
    dependencies=[Depends(verify_admin_access)],
    responses={
        200: {"description": "Credential deleted successfully."},
        404: {"description": "Credential not found."},
        500: {"description": "Internal server error during deletion."},
    }
)
async def delete_credential_api(
    credential_id: str,
    cred_manager: CredentialManager = Depends(get_credential_manager)
):
    """
    从池中删除指定的凭据。
    """
    ok, reason = await cred_manager.delete_credential(credential_id)
    if ok:
        return JSONResponse(content={"status": "success", "message": reason})
    elif reason == "credential_not_found":
        raise HTTPException(status_code=404, detail=f"Credential with id '{credential_id}' not found.")
    else:
        raise HTTPException(status_code=500, detail=f"Failed to delete credential: {reason}")
