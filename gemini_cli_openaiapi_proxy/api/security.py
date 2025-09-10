"""
API 安全模块：
- 负责处理 API 密钥的认证。
"""

import base64
from typing import List
from fastapi import Request, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader, APIKeyQuery, APIKeyCookie

API_KEY_NAME = "Authorization"
API_KEY_QUERY_NAME = "key"
GCP_API_KEY_HEADER_NAME = "x-goog-api-key"

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
api_key_query = APIKeyQuery(name=API_KEY_QUERY_NAME, auto_error=False)
gcp_api_key_header = APIKeyHeader(name=GCP_API_KEY_HEADER_NAME, auto_error=False)

async def get_api_key(
    request: Request,
    key_from_header: str = Security(api_key_header),
    key_from_query: str = Security(api_key_query),
    key_from_gcp_header: str = Security(gcp_api_key_header),
) -> str:
    """
    从多个位置获取 API 密钥，并进行验证。
    """
    # 1. 从 Authorization: Bearer ... 获取
    if key_from_header and key_from_header.startswith("Bearer "):
        token = key_from_header.split(" ")[1]
        if token in request.app.state.settings["auth_keys"]:
            return token

    # 2. 从 HTTP Basic Auth 获取
    if key_from_header and key_from_header.startswith("Basic "):
        try:
            encoded = key_from_header.split(" ")[1]
            decoded = base64.b64decode(encoded).decode("utf-8")
            _, password = decoded.split(":", 1)
            if password in request.app.state.settings["auth_keys"]:
                return password
        except Exception:
            pass # 忽略解析错误

    # 3. 从 Query 参数 ?key=... 获取
    if key_from_query and key_from_query in request.app.state.settings["auth_keys"]:
        return key_from_query

    # 4. 从 x-goog-api-key 头获取
    if key_from_gcp_header and key_from_gcp_header in request.app.state.settings["auth_keys"]:
        return key_from_gcp_header

    raise HTTPException(
        status_code=401,
        detail="Invalid or missing API Key. Provide it via 'Authorization: Bearer <key>', 'Authorization: Basic ...', '?key=<key>', or 'x-goog-api-key' header.",
        headers={"WWW-Authenticate": "Basic"},
    )
