"""
凭据管理：
- 仅持久化四字段：access_token、refresh_token、token_type、expiry_date(ms)。
- 支持单对象或数组格式；导入外部文件时按 refresh_token 去重合并。
- email 获取：优先使用 id_token 解码；否则调用 userinfo 接口；失败则视为失效。
- project_id 解析顺序：config.project_id_map[email] -> API 发现 -> 失效。
- 轮转与刷新：到期前刷新；429 标记 exhausted；状态仅在内存维护。
"""
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

from .config import CLIENT_ID, CLIENT_SECRET, SCOPES, CODE_ASSIST_ENDPOINT
from .utils import get_user_agent, get_client_metadata


def _ms_to_datetime(ms: int) -> datetime:
    """毫秒时间戳转 UTC datetime。"""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


def _datetime_to_ms(dt: datetime) -> int:
    """UTC datetime 转毫秒时间戳（容忍 naive，按 UTC 处理）。"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _build_credentials_from_simple(simple: Dict[str, Any]) -> Credentials:
    """由四字段构造 Google Credentials。"""
    token = simple.get("access_token")
    refresh_token = simple.get("refresh_token")
    token_type = simple.get("token_type", "Bearer")
    expiry_ms = simple.get("expiry_date")

    info = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "token": token,
        "refresh_token": refresh_token,
        "token_uri": "https://oauth2.googleapis.com/token",
        "scopes": SCOPES,
    }
    creds = Credentials.from_authorized_user_info(info, SCOPES)
    if expiry_ms:
        creds.expiry = _ms_to_datetime(int(expiry_ms))
        # 统一将 expiry 归一为 naive UTC，避免比较错误
        _normalize_expiry_to_naive_utc(creds)
    return creds


def _credentials_to_simple(creds: Credentials) -> Dict[str, Any]:
    """将 Credentials 转为四字段。"""
    # 将 naive UTC 看作 UTC 处理
    expiry_ms = _datetime_to_ms(creds.expiry) if creds.expiry else None
    return {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_type": "Bearer",
        "expiry_date": expiry_ms,
    }


def _normalize_expiry_to_naive_utc(creds: Credentials) -> None:
    """将 Credentials.expiry 统一为 naive UTC，避免与库内部 naive 比较报错。"""
    try:
        if creds and getattr(creds, "expiry", None):
            dt = creds.expiry
            if dt.tzinfo is not None:
                creds.expiry = dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        pass


def _get_email_from_credentials(creds: Credentials) -> Optional[str]:
    """从凭据推导 email。优先 id_token，其次 userinfo。"""
    # 1) id_token
    try:
        if getattr(creds, "id_token", None):
            # 尝试使用 OIDC userinfo 端点验证并取 email（即便本地解析失败）
            headers = {"Authorization": f"Bearer {creds.id_token}"}
            resp = requests.get("https://openidconnect.googleapis.com/v1/userinfo", headers=headers, timeout=10)
            if resp.ok:
                data = resp.json()
                if data.get("email"):
                    return data["email"]
    except Exception:
        pass

    # 2) access_token
    try:
        headers = {"Authorization": f"Bearer {creds.token}"}
        resp = requests.get("https://openidconnect.googleapis.com/v1/userinfo", headers=headers, timeout=10)
        if resp.ok:
            data = resp.json()
            if data.get("email"):
                return data["email"]
    except Exception:
        pass
    return None


def _discover_project_id(creds: Credentials) -> Optional[str]:
    """通过 API 发现 project_id。"""
    try:
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleAuthRequest())
        headers = {
            "Authorization": f"Bearer {creds.token}",
            "Content-Type": "application/json",
            "User-Agent": get_user_agent(),
        }
        payload = {"metadata": get_client_metadata()}
        resp = requests.post(f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist", data=json.dumps(payload), headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        pid = data.get("cloudaicompanionProject")
        return pid
    except Exception:
        return None


class CredentialStatus:
    ACTIVE = "active"
    EXPIRED = "expired"
    REFRESHING = "refreshing"
    EXHAUSTED = "exhausted"
    ERROR = "error"


@dataclass
class ManagedCredential:
    id: str
    credentials: Credentials
    project_id: Optional[str]
    email: Optional[str]
    status: str = CredentialStatus.ACTIVE
    last_used: datetime = datetime.now()
    usage_count: int = 0
    exhausted_until: Optional[datetime] = None

    def is_available(self) -> bool:
        now = datetime.now()
        if self.status in [CredentialStatus.EXPIRED, CredentialStatus.ERROR]:
            return False
        if self.status == CredentialStatus.EXHAUSTED and self.exhausted_until and now < self.exhausted_until:
            return False
        if self.credentials.expired:
            self.status = CredentialStatus.EXPIRED
            return False
        return True

    def mark_used(self):
        self.last_used = datetime.now()
        self.usage_count += 1

    def mark_exhausted(self, minutes: int = 30):
        self.status = CredentialStatus.EXHAUSTED
        self.exhausted_until = datetime.now() + timedelta(minutes=minutes)


class CredentialManager:
    """统一的凭据池管理。"""

    def __init__(self, settings: Dict[str, Any]):
        self.settings = settings
        self.credentials: List[ManagedCredential] = []
        self.current_index = 0
        self.lock = threading.Lock()
        self.refresh_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.refresh_interval_sec = 300

    # ===== 持久化读写 =====
    def _read_file(self, path: str) -> List[Dict[str, Any]]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return []
        except Exception as e:
            logging.error(f"Failed to read credentials file: {e}")
            return []

        if isinstance(data, dict):
            # 单对象
            return [data]
        elif isinstance(data, list):
            return data
        else:
            logging.warning("Invalid credentials file format; expecting object or array")
            return []

    def _write_file(self, path: str, items: List[Dict[str, Any]]):
        out: Any = items[0] if len(items) == 1 else items
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)

    # ===== 导入与加载 =====
    def import_external(self):
        ext = self.settings.get("external_credentials_file")
        if not ext:
            return
        existing = self._read_file(self.settings["credentials_file"])
        incoming = self._read_file(ext)
        merged = self._merge_by_refresh_token(existing, incoming)
        self._write_file(self.settings["credentials_file"], merged)

    @staticmethod
    def _merge_by_refresh_token(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = {}
        for item in a + b:
            rt = item.get("refresh_token")
            if rt and rt not in seen:
                seen[rt] = item
            elif rt:
                # 覆盖为后者（通常外部导入较新）
                seen[rt] = item
        return list(seen.values())

    def load(self):
        simple_items = self._read_file(self.settings["credentials_file"])
        logging.info(f"Loading credentials from file, count={len(simple_items)}")
        self.credentials = []
        for idx, item in enumerate(simple_items):
            try:
                creds = _build_credentials_from_simple(item)
                email = _get_email_from_credentials(creds)
                if not email:
                    logging.warning("Credential missing email; mark as invalid and skip")
                    continue
                # project_id 映射优先
                pid = self.settings.get("project_id_map", {}).get(email)
                if not pid:
                    logging.info(f"project_id not found in map for {email}, discovering via API...")
                    pid = _discover_project_id(creds)
                if not pid:
                    logging.warning(f"Credential for {email} has no project_id; mark as invalid and skip")
                    continue
                mc = ManagedCredential(id=f"cred-{idx}", credentials=creds, project_id=pid, email=email)
                self.credentials.append(mc)
                logging.info(f"Loaded credential: id={mc.id}, email={email}, project={pid}")
            except Exception as e:
                logging.warning(f"Skipping invalid credential: {e}")

    # ===== 选择与轮转 =====
    def get_available(self) -> Optional[ManagedCredential]:
        with self.lock:
            n = len(self.credentials)
            if n == 0:
                return None
            start = self.current_index
            for _ in range(n):
                c = self.credentials[self.current_index]
                if c.is_available():
                    c.mark_used()
                    self.current_index = (self.current_index + 1) % n
                    return c
                self.current_index = (self.current_index + 1) % n
            # 尝试刷新过期的
            for c in self.credentials:
                if c.status == CredentialStatus.EXPIRED and c.credentials.refresh_token:
                    if self._refresh_credential(c):
                        c.mark_used()
                        return c
            return None

    def mark_exhausted(self, cred_id: str, minutes: int = 30):
        with self.lock:
            for c in self.credentials:
                if c.id == cred_id:
                    c.mark_exhausted(minutes)
                    logging.warning(f"Marked exhausted: id={cred_id} for {minutes} minutes")
                    break

    # ===== 刷新与后台任务 =====
    def _refresh_credential(self, c: ManagedCredential) -> bool:
        try:
            c.credentials.refresh(GoogleAuthRequest())
            _normalize_expiry_to_naive_utc(c.credentials)
            # 刷新成功后立即落盘
            self._persist_current()
            c.status = CredentialStatus.ACTIVE
            return True
        except Exception as e:
            logging.error(f"Refresh failed for {c.email}: {e}")
            c.status = CredentialStatus.ERROR
            return False

    def _persist_current(self):
        items: List[Dict[str, Any]] = []
        for c in self.credentials:
            items.append(_credentials_to_simple(c.credentials))
        self._write_file(self.settings["credentials_file"], items)
        logging.info("Persisted credentials to file (simple format)")

    def _refresh_loop(self):
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    for c in self.credentials:
                        if not c.credentials.expiry:
                            continue
                        # 提前 60s 刷新（统一使用 naive UTC，避免 tz 混用）
                        try:
                            exp = c.credentials.expiry
                            if exp.tzinfo is not None:
                                exp = exp.astimezone(timezone.utc).replace(tzinfo=None)
                        except Exception:
                            exp = c.credentials.expiry
                        now_naive = datetime.utcnow()
                        if (exp - now_naive) < timedelta(seconds=60):
                            if c.credentials.refresh_token:
                                self._refresh_credential(c)
                self.stop_event.wait(self.refresh_interval_sec)
            except Exception as e:
                logging.error(f"Refresh loop error: {e}")
                self.stop_event.wait(self.refresh_interval_sec)

    def start_refresh_task(self):
        if self.refresh_thread and self.refresh_thread.is_alive():
            return
        self.stop_event.clear()
        self.refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self.refresh_thread.start()

    def stop_refresh_task(self):
        self.stop_event.set()
        if self.refresh_thread and self.refresh_thread.is_alive():
            self.refresh_thread.join(timeout=5)

    # ===== 统计 =====
    def get_credential_count(self) -> int:
        return len(self.credentials)

    def get_active_credential_count(self) -> int:
        return sum(1 for c in self.credentials if c.is_available())

    # ===== 新增：添加凭据（用于 OAuth 流程） =====
    def add_credentials(self, creds: Credentials) -> Tuple[bool, Optional[str]]:
        """
        添加一条凭据到池：
        - 基于 refresh_token 去重；重复则返回 (False, reason)。
        - 解析 email；根据配置映射/接口发现 project_id；失败则返回 (False, reason)。
        - 成功则持久化四字段，并返回 (True, None)。
        """
        try:
            # 去重: refresh_token
            rt = creds.refresh_token
            if not rt:
                return False, "missing_refresh_token"
            with self.lock:
                for c in self.credentials:
                    if c.credentials.refresh_token == rt:
                        logging.warning("Duplicate credential by refresh_token; skip add")
                        return False, "duplicate_refresh_token"

            email = _get_email_from_credentials(creds)
            if not email:
                return False, "missing_email"
            pid = self.settings.get("project_id_map", {}).get(email)
            if not pid:
                logging.info(f"project_id not found in map for {email}, discovering via API...")
                pid = _discover_project_id(creds)
            if not pid:
                return False, "missing_project_id"
            
            with self.lock: 
                for existing_cred in self.credentials:
                    if existing_cred.email == email:
                        logging.warning(f"Adding credential for email '{email}' which already exists in the pool (ID: {existing_cred.id}). This credential will be added as a separate entry.")
                        break # 找到一个就够了，跳出循环

            mc = ManagedCredential(id=f"cred-{len(self.credentials)}", credentials=creds, project_id=pid, email=email)
            with self.lock:
                self.credentials.append(mc)
                self._persist_current()
            logging.info(f"Added credential: email={email}, project={pid}")
            return True, None
        except Exception as e:
            logging.error(f"Failed to add credential: {e}")
            return False, "exception"


