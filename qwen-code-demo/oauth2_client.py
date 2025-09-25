"""
Qwen OAuth2 客户端实现
封装设备授权（Device Code + PKCE）、令牌轮询与刷新、凭据管理
"""
import json
import time
import httpx
from typing import Dict, Any, Optional
from .config import (
    QWEN_OAUTH_DEVICE_CODE_ENDPOINT,
    QWEN_OAUTH_TOKEN_ENDPOINT,
    QWEN_OAUTH_CLIENT_ID,
    QWEN_OAUTH_SCOPE,
    QWEN_OAUTH_GRANT_TYPE,
    POLL_INTERVAL,
    MAX_POLL_ATTEMPTS,
    USER_AGENT
)
from .pkce import generate_pkce_pair


class QwenOAuth2Client:
    """
    Qwen OAuth2 客户端
    负责：
    - 申请设备授权（提交 PKCE code_challenge）
    - 轮询令牌（携带 PKCE code_verifier）
    - 刷新访问令牌
    - 维护与导出凭据
    """
    def __init__(self):
        self.credentials: Dict[str, Any] = {}
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_type: Optional[str] = None
        self.expiry_date: Optional[int] = None
        self.resource_url: Optional[str] = None
        self.code_verifier: Optional[str] = None

    def request_device_authorization(self) -> Dict[str, Any]:
        """
        申请设备授权（Device Authorization）
        返回设备授权响应（包含 device_code / user_code / 验证地址等）
        """
        pkce_pair = generate_pkce_pair()
        code_challenge = pkce_pair['code_challenge']
        
        data = {
            'client_id': QWEN_OAUTH_CLIENT_ID,
            'scope': QWEN_OAUTH_SCOPE,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }

        # 与 Node 实现一致，使用 x-www-form-urlencoded
        encoded_data = '&'.join(f'{key}={value}' for key, value in data.items())
        
        response = httpx.post(
            QWEN_OAUTH_DEVICE_CODE_ENDPOINT,
            content=encoded_data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'User-Agent': USER_AGENT
            },
            timeout=30
        )

        if response.status_code != 200:
            raise Exception(f"设备授权失败：{response.status_code} {response.text}")

        try:
            result = response.json()
        except ValueError:
            raise Exception(f"设备授权返回的 JSON 无法解析：{response.text}")
        
        # 暂存 code_verifier 用于后续轮询
        self.code_verifier = pkce_pair['code_verifier']
        
        return result

    def poll_for_token(self, device_code: str) -> Dict[str, Any]:
        """
        轮询令牌端点以获取访问令牌
        参数:
            device_code: 设备授权阶段返回的 device_code
        """
        data = {
            'grant_type': QWEN_OAUTH_GRANT_TYPE,
            'client_id': QWEN_OAUTH_CLIENT_ID,
            'device_code': device_code,
            'code_verifier': self.code_verifier
        }

        for attempt in range(MAX_POLL_ATTEMPTS):
            encoded_data = '&'.join(f'{key}={value}' for key, value in data.items())
            
            response = httpx.post(
                QWEN_OAUTH_TOKEN_ENDPOINT,
                content=encoded_data,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json',
                    'User-Agent': USER_AGENT
                },
                timeout=30
            )

            if response.status_code == 200:
                token_data = response.json()
                self._update_credentials(token_data)
                return token_data
            elif response.status_code == 400:
                # 标准设备码错误处理（RFC 8628）
                try:
                    error_data = response.json()
                except ValueError:
                    raise Exception(f"令牌轮询返回的错误 JSON 无法解析：{response.text}")
                
                error = error_data.get('error', '')
                
                if error == 'authorization_pending':
                    print(f"等待用户授权中...（{attempt + 1}/{MAX_POLL_ATTEMPTS}）")
                    time.sleep(POLL_INTERVAL)
                    continue
                elif error == 'slow_down':
                    print("服务器要求降低轮询频率，正在放慢...")
                    time.sleep(POLL_INTERVAL * 1.5)
                    continue
                elif error == 'access_denied':
                    raise Exception("用户拒绝授权：access_denied")
                elif error == 'expired_token':
                    raise Exception("设备码已过期：请重新开始授权流程")
                else:
                    raise Exception(f"令牌请求失败：{error} - {error_data.get('error_description', '')}")
            else:
                raise Exception(f"令牌请求失败（HTTP {response.status_code}）：{response.text}")

        raise Exception("令牌轮询超时，请稍后重试")

    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        使用 refresh_token 刷新访问令牌
        返回刷新结果 JSON
        """
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': QWEN_OAUTH_CLIENT_ID
        }

        encoded_data = '&'.join(f'{key}={value}' for key, value in data.items())
        
        response = httpx.post(
            QWEN_OAUTH_TOKEN_ENDPOINT,
            content=encoded_data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'User-Agent': USER_AGENT
            },
            timeout=30
        )

        if response.status_code != 200:
            raise Exception(f"刷新访问令牌失败：{response.status_code} {response.text}")

        try:
            token_data = response.json()
        except ValueError:
            raise Exception(f"刷新令牌返回的 JSON 无法解析：{response.text}")
        
        self._update_credentials(token_data)
        return token_data

    def _update_credentials(self, token_data: Dict[str, Any]):
        """
        将返回的 token 数据更新到客户端状态
        """
        self.access_token = token_data.get('access_token')
        self.refresh_token = token_data.get('refresh_token', self.refresh_token)  # 若未返回则沿用旧值
        self.token_type = token_data.get('token_type')
        self.resource_url = token_data.get('resource_url')
        
        # 计算过期时间（毫秒）
        expires_in = token_data.get('expires_in', 3600)
        self.expiry_date = int(time.time() * 1000) + (expires_in * 1000)

    def get_credentials(self) -> Dict[str, Any]:
        """
        导出当前凭据（便于持久化）
        """
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_type': self.token_type,
            'expiry_date': self.expiry_date,
            'resource_url': self.resource_url
        }

    def is_token_valid(self) -> bool:
        """
        校验当前令牌是否仍有效（含 30 秒缓冲）
        """
        if not self.expiry_date or not self.access_token:
            return False
        current_time = int(time.time() * 1000)
        return current_time < (self.expiry_date - 30000)  # 30 秒缓冲