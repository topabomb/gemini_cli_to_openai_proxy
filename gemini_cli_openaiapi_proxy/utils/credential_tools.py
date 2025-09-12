"""
凭据处理工具模块。

提供凭据序列化/反序列化、项目ID发现等类型安全的工具函数，
供服务端和客户端共享使用。
"""
import logging
from typing_extensions import Any, Dict, List, Optional, TypedDict
from google.oauth2.credentials import Credentials
import httpx
from pydantic import BaseModel

from ..core.config import CLIENT_ID, CLIENT_SECRET, SCOPES, CODE_ASSIST_ENDPOINT
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ===== 数据模型 =====

class SimpleCredential(TypedDict, total=False):
    """
    一个类型化的字典，用于表示凭据中可被序列化的核心字段。
    `total=False` 允许 `project_id` 等键为可选，以实现向后兼容。
    """
    access_token: Optional[str]
    refresh_token: Optional[str]
    token_type: str
    expiry_date: Optional[int]  # 毫秒时间戳
    scopes: List[str]
    project_id: Optional[str]

class AddCredentialRequest(BaseModel):
    """用于添加新凭据请求的 Pydantic 模型。"""
    credential: SimpleCredential

# ===== 序列化/反序列化 =====

def _datetime_to_ms(dt: datetime) -> int:
    """将 UTC datetime 对象转换为毫秒时间戳。"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)

def _ms_to_datetime(ms: int) -> datetime:
    """将毫秒时间戳转换为 UTC datetime 对象。"""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)

def credentials_to_simple(creds: Credentials,project_id:Optional[str]) -> SimpleCredential:
    """将 Credentials 对象序列化为 SimpleCredential 字典。"""
    expiry_ms = _datetime_to_ms(creds.expiry) if creds.expiry else None
    simple: SimpleCredential = {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_type": "Bearer",
        "expiry_date": expiry_ms,
        "scopes": creds.scopes or [],
        "project_id": project_id,
    }
    return simple

def build_credentials_from_simple(simple: SimpleCredential) -> Credentials:
    """从 SimpleCredential 字典构建一个 Credentials 对象。"""
    scopes_to_use = simple.get("scopes")
    if not scopes_to_use:
        scopes_to_use = SCOPES
        logger.debug("Building credential. Scopes not in file, falling back to constant: %s", scopes_to_use)

    info = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "token": simple.get("access_token"),
        "refresh_token": simple.get("refresh_token"),
        "token_uri": "https://oauth2.googleapis.com/token",
        "scopes": scopes_to_use,
    }
    creds = Credentials.from_authorized_user_info(info, scopes_to_use)
    if expiry_ms := simple.get("expiry_date"):
        creds.expiry = _ms_to_datetime(int(expiry_ms))
    return creds

# ===== Project ID 发现 =====

async def get_email_from_credentials(creds: Credentials, http_client: httpx.AsyncClient) -> Optional[str]:
    """使用给定的凭据获取用户的电子邮件地址。"""
    headers = {"Authorization": f"Bearer {creds.token}"}
    try:
        resp = await http_client.get("https://openidconnect.googleapis.com/v1/userinfo", headers=headers, timeout=10)
        if resp.is_success:
            return resp.json().get("email")
    except Exception as e:
        logger.warning(f"Failed to get email via userinfo endpoint: {e}")
    return None

async def discover_project_id(creds: Credentials, http_client: httpx.AsyncClient) -> Optional[str]:
    """发现与凭据关联的 GCP 项目 ID。"""
    headers = {"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"}
    payload = {"metadata": {}}
    try:
        resp = await http_client.post(f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist", json=payload, headers=headers, timeout=20)
        resp.raise_for_status()
        return resp.json().get("cloudaicompanionProject")
    except Exception as e:
        logger.warning(f"Failed to discover project_id via API: {e}")
        return None

async def determine_project_id(
    creds: Credentials,
    project_id_map: Dict[str, str],
    http_client: httpx.AsyncClient
) -> Optional[str]:
    """
    通过一个基于优先级的策略来确定项目ID：
    1. 检查配置中提供的 `project_id_map`。
    2. 回退到通过 API 调用进行发现。
    """
    email = await get_email_from_credentials(creds, http_client)
    if not email:
        logger.warning("Could not determine project ID because email could not be fetched.")
        return None

    # 1. 首先检查映射表
    if project_id := project_id_map.get(email):
        logger.info(f"Found project ID '{project_id}' in config map for email '{email}'.")
        return project_id

    # 2. 回退到 API 发现
    logger.info(f"Project ID for '{email}' not in config map, attempting API discovery.")
    return await discover_project_id(creds, http_client)
