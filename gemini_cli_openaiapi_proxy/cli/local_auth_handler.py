"""
此模块处理 'auth' CLI 命令的本地 OAuth2 流程。
"""
import asyncio
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import httpx
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest
from ..core.config import SettingsDict, CLIENT_ID, CLIENT_SECRET, SCOPES
from ..utils.credential_tools import credentials_to_simple, determine_project_id

class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    """一个简单的 HTTP 处理器，用于捕获 OAuth2 回调。"""
    auth_code = None
    error = None

    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        if 'code' in query_components:
            _OAuthCallbackHandler.auth_code = query_components["code"][0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<h1>Authentication Successful!</h1><p>You can close this window now.</p>")
        else:
            _OAuthCallbackHandler.error = query_components.get("error", ["Unknown error"])[0]
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"<h1>Authentication Failed</h1><p>Reason: {self.error}. Please try again.</p>".encode())

    def log_message(self, format, *args):
        # 抑制日志记录以保持控制台干净
        return

async def execute_local_oauth_flow(settings: SettingsDict):
    """
    协调从开始到结束的整个本地 OAuth2 流程。
    """
    # 为 project_id 发现创建一个临时的 http 客户端
    async with httpx.AsyncClient() as client:
        await _execute_flow_with_client(settings, client)

async def _execute_flow_with_client(settings: SettingsDict, client: httpx.AsyncClient):
    # 1. 验证配置
    auth_client_config = settings.get("auth_client")
    if not auth_client_config or not all(k in auth_client_config for k in ["proxy_url", "admin_username", "admin_password"]):
        print("[ERROR] 'auth_client' section is missing or incomplete in your config file.", file=sys.stderr)
        print("Please add 'proxy_url', 'admin_username', and 'admin_password' to the 'auth_client' section.", file=sys.stderr)
        sys.exit(1)

    # 2. 在动态端口上设置本地服务器
    try:
        server = HTTPServer(('127.0.0.1', 0), _OAuthCallbackHandler)
        redirect_uri = f"http://127.0.0.1:{server.server_address[1]}"
    except Exception as e:
        print(f"\n[ERROR] Failed to start local callback server: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. 创建 OAuth 流程并获取授权 URL
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
    authorization_url, _ = flow.authorization_url(access_type="offline", prompt="consent")

    # 4. 提示用户并等待授权码
    print("Your browser has been opened to visit:")
    print(f"\n{authorization_url}\n")
    print("Please follow the instructions in your browser to complete authentication.")
    webbrowser.open(authorization_url)

    server.handle_request() # 处理一个请求然后关闭
    server.server_close()

    auth_code = _OAuthCallbackHandler.auth_code
    auth_error = _OAuthCallbackHandler.error

    if auth_error:
        print(f"\n[ERROR] Authentication failed in browser: {auth_error}", file=sys.stderr)
        sys.exit(1)
    if not auth_code:
        print("\n[ERROR] Could not retrieve authorization code. Please try again.", file=sys.stderr)
        sys.exit(1)

    print("\nAuthentication code received, exchanging for refresh token...")

    # 5. 交换授权码以获取令牌
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: flow.fetch_token(code=auth_code))
    except Exception as e:
        print(f"\n[ERROR] Failed to exchange authorization code for token: {e}", file=sys.stderr)
        sys.exit(1)

    from google.oauth2.credentials import Credentials

    creds = flow.credentials
    if not isinstance(creds, Credentials) or not creds.refresh_token:
        print("\n[ERROR] Failed to obtain a valid credential with a refresh token.", file=sys.stderr)
        print("Please ensure you are granting offline access to a standard Google account.", file=sys.stderr)
        sys.exit(1)

    print("Refresh token obtained, refreshing access token before submission...")

    # 6. 在客户端刷新令牌以确保 access_token 有效
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, creds.refresh, GoogleAuthRequest())
    except Exception as e:
        print(f"\n[ERROR] Failed to refresh the access token: {e}", file=sys.stderr)
        sys.exit(1)

    print("Access token refreshed, submitting to proxy server...")

    # 7. 确定项目 ID
    print("Attempting to determine project ID...")
    project_id_map = settings.get("project_id_map", {})
    project_id = await determine_project_id(creds, project_id_map, client)

    if not project_id:
        print("\n[ERROR] Could not determine Project ID.", file=sys.stderr)
        print("Please ensure your account has an active GCP project, or add it to the 'project_id_map' in your config file.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Project ID '{project_id}' determined successfully.")
    print("Submitting credential and project ID to proxy server...")

    # 8. 将序列化的凭据（内嵌 project_id）提交到代理服务器
    proxy_url = auth_client_config["proxy_url"].rstrip('/')
    admin_user = auth_client_config["admin_username"]
    admin_pass = auth_client_config["admin_password"]
    
    # 序列化凭据并直接嵌入 project_id
    simple_cred = credentials_to_simple(creds,project_id)
    
    payload = {"credential": simple_cred}

    try:
        response = await client.post(
            f"{proxy_url}/admin/credentials/add",
            json=payload,
            auth=(admin_user, admin_pass),
            timeout=30
        )
        response.raise_for_status()
        
        result = response.json()
        email = result.get("email", "N/A")
        message = result.get("message", "No message returned.")
        print(f"\n[SUCCESS] Credential for '{email}' processed successfully: {message}")

    except httpx.ConnectError:
        print(f"\n[ERROR] Connection to proxy server at '{proxy_url}' failed.", file=sys.stderr)
        print("Please ensure the proxy server is running and the 'proxy_url' in your config is correct.", file=sys.stderr)
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            print("\n[ERROR] Authentication failed with the proxy server.", file=sys.stderr)
            print("Please check that 'admin_username' and 'admin_password' in the 'auth_client' section of your config are correct.", file=sys.stderr)
        else:
            error_detail = e.response.json().get("detail", e.response.text)
            print(f"\n[ERROR] Proxy server returned an error (HTTP {e.response.status_code}): {error_detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred while communicating with the proxy: {e}", file=sys.stderr)
        sys.exit(1)
